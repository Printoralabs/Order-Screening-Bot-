import os
import re
import json
import base64
import hashlib
import hmac
import time
import threading
from urllib.parse import urlparse

import requests
import resend
from flask import Flask, request

try:
    from rapidfuzz import fuzz
except ImportError:
    fuzz = None


app = Flask(__name__)


# ============================================================
# CONFIGURATION
# ============================================================

SHOPIFY_DOMAIN = os.environ.get("SHOPIFY_DOMAIN", "").strip()

# Existing/static token support
SHOPIFY_TOKEN = os.environ.get("SHOPIFY_TOKEN", "").strip()

# Optional Shopify client-credentials support
SHOPIFY_CLIENT_ID = os.environ.get("SHOPIFY_CLIENT_ID", "").strip()
SHOPIFY_CLIENT_SECRET = os.environ.get("SHOPIFY_CLIENT_SECRET", "").strip()

# Shopify webhook HMAC uses the Shopify Client Secret directly.
# No separate SHOPIFY_WEBHOOK_SECRET environment variable is required.

ANTHROPIC_KEY = os.environ.get("ANTHROPIC_KEY", "").strip()

# Can be changed in Render without editing code
ANTHROPIC_MODEL = os.environ.get(
    "ANTHROPIC_MODEL",
    "claude-sonnet-5"
).strip()

ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "").strip()
RESEND_KEY = os.environ.get("RESEND_KEY", "").strip()

# Use your verified Resend sender in production.
# onboarding@resend.dev can be used for initial testing where supported.
RESEND_FROM = os.environ.get(
    "RESEND_FROM",
    "onboarding@resend.dev"
).strip()

SHOPIFY_API_VERSION = os.environ.get(
    "SHOPIFY_API_VERSION",
    "2026-10"
).strip()


# ============================================================
# STATE
# ============================================================

# Prevent the same webhook from being processed twice
processed_webhooks = set()
processed_lock = threading.Lock()

# Shopify client-credentials token cache
shopify_token_cache = {
    "token": None,
    "expires_at": 0
}

shopify_token_lock = threading.Lock()


# ============================================================
# SAFETY KEYWORDS
# ============================================================

# These are intentionally broad because the goal is to send
# suspicious products to MANUAL REVIEW, not automatically reject
# legitimate products.

DANGEROUS_TERMS = {
    # Firearms
    "gun",
    "guns",
    "firearm",
    "firearms",
    "pistol",
    "pistols",
    "rifle",
    "rifles",
    "shotgun",
    "shotguns",
    "handgun",
    "handguns",
    "revolver",
    "machinegun",
    "smg",

    # Ammunition
    "ammunition",
    "ammo",
    "bullet",
    "bullets",
    "cartridge",
    "cartridges",

    # Explosives
    "bomb",
    "bombs",
    "grenade",
    "grenades",
    "explosive",
    "explosives",
    "detonator",
    "detonators",

    # Weapons
    "switchblade",
    "switchblades",
    "machete",
    "machetes",
    "brassknuckles",
    "brassknuckle",
    "knuckle duster",
    "knuckleduster",
    "crossbow",
    "crossbows",
    "spear",
    "spears",
    "sword",
    "swords",
    "dagger",
    "daggers",

    # Electrical weapons
    "taser",
    "tasers",
    "stungun",
    "stunguns",

    # Chemical/self-defense weapons
    "pepperspray",
    "peppersprays",
    "pepper spray",

    # Weapon components / accessories
    "silencer",
    "suppressor",
    "suppressors",
    "magazine",
    "magazines",
    "trigger",
    "triggers",
    "gunstock",
    "gunstocks",
    "receiver",
    "receivers",
}


# Terms that are suspicious enough to require AI/manual review
SUSPICIOUS_TERMS = {
    "weapon",
    "weapons",
    "tactical",
    "combat",
    "ballistic",
    "armory",
    "arsenal",
    "concealed",
    "self defense",
    "selfdefense",
}


# ============================================================
# TEXT NORMALIZATION
# ============================================================

LEET_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
    "!": "i",
})


def normalize_text(text):
    """
    Makes text easier to compare.

    Examples:
        gUn       -> gun
        G.U.N     -> gun
        g u n     -> gun
        gUn123    -> gun123
        kn1fe     -> knife
    """

    if not text:
        return ""

    text = str(text).lower()

    # Normalize common leetspeak
    text = text.translate(LEET_TRANSLATION)

    # Remove accents where possible
    text = text.encode(
        "ascii",
        "ignore"
    ).decode(
        "ascii"
    )

    # Turn punctuation into spaces
    text = re.sub(
        r"[^a-z0-9]+",
        " ",
        text
    )

    # Collapse whitespace
    text = re.sub(
        r"\s+",
        " ",
        text
    ).strip()

    return text


def compact_text(text):
    """
    Removes spaces so:
        'stun gun' -> 'stungun'
        'pepper spray' -> 'pepperspray'
    """

    return normalize_text(text).replace(" ", "")


# ============================================================
# FUZZY MATCHING
# ============================================================

def fuzzy_keyword_match(text):
    """
    Detects misspellings and altered versions of dangerous terms.

    Examples that can be caught:
        gun
        gunn
        g u n
        g.un
        gUn
        knief
        wepon
        pist0l
    """

    normalized = normalize_text(text)
    compact = compact_text(text)

    if not normalized:
        return None

    # Exact substring checks first
    for term in DANGEROUS_TERMS:
        term_normalized = normalize_text(term)
        term_compact = compact_text(term)

        if term_normalized in normalized:
            return f"Exact safety term: {term}"

        if term_compact and term_compact in compact:
            return f"Normalized safety term: {term}"

    # Fuzzy matching
    if fuzz is None:
        return None

    words = normalized.split()

    for term in DANGEROUS_TERMS:
        term_normalized = normalize_text(term)

        # Don't fuzzy-match extremely short terms aggressively.
        # This reduces false positives.
        if len(term_normalized) < 4:
            continue

        for word in words:

            if len(word) < 3:
                continue

            score = fuzz.ratio(
                word,
                term_normalized
            )

            # Strong similarity
            if score >= 88:
                return (
                    f"Fuzzy safety match: "
                    f"{word} ~ {term} ({score:.0f}%)"
                )

            # Slightly more tolerant for longer words
            if len(term_normalized) >= 7 and score >= 80:
                return (
                    f"Fuzzy safety match: "
                    f"{word} ~ {term} ({score:.0f}%)"
                )

    return None


# ============================================================
# SHOPIFY TOKEN
# ============================================================

def get_shopify_token():
    """
    Supports:
    1. Existing SHOPIFY_TOKEN
    2. Shopify client-credentials flow

    Client-credentials tokens expire after 24 hours, so the
    application refreshes them automatically when needed.
    """

    # If we only have the existing token, use it.
    if not SHOPIFY_CLIENT_ID or not SHOPIFY_CLIENT_SECRET:
        return SHOPIFY_TOKEN

    now = time.time()

    with shopify_token_lock:

        cached_token = shopify_token_cache["token"]
        expires_at = shopify_token_cache["expires_at"]

        # Keep a safety margin before expiration
        if (
            cached_token
            and expires_at > now + 300
        ):
            return cached_token

        token_url = (
            f"https://{SHOPIFY_DOMAIN}"
            "/admin/oauth/access_token"
        )

        response = requests.post(
            token_url,
            headers={
                "Content-Type":
                    "application/x-www-form-urlencoded"
            },
            data={
                "client_id":
                    SHOPIFY_CLIENT_ID,
                "client_secret":
                    SHOPIFY_CLIENT_SECRET,
                "grant_type":
                    "client_credentials",
            },
            timeout=20,
        )

        response.raise_for_status()

        data = response.json()

        token = data.get(
            "access_token"
        )

        expires_in = int(
            data.get(
                "expires_in",
                86399
            )
        )

        if not token:
            raise RuntimeError(
                "Shopify did not return an access token."
            )

        shopify_token_cache["token"] = token
        shopify_token_cache["expires_at"] = (
            time.time() + expires_in
        )

        print(
            "Shopify access token refreshed."
        )

        return token


# ============================================================
# SHOPIFY GRAPHQL
# ============================================================

def shopify_graphql(query, variables=None):
    token = get_shopify_token()

    if not token:
        raise RuntimeError(
            "No Shopify API token configured."
        )

    url = (
        f"https://{SHOPIFY_DOMAIN}"
        f"/admin/api/{SHOPIFY_API_VERSION}"
        "/graphql.json"
    )

    response = requests.post(
        url,
        headers={
            "X-Shopify-Access-Token": token,
            "Content-Type": "application/json",
        },
        json={
            "query": query,
            "variables": variables or {},
        },
        timeout=25,
    )

    # If the cached token expired, try once more with a fresh token
    if response.status_code == 401:
        with shopify_token_lock:
            shopify_token_cache["token"] = None
            shopify_token_cache["expires_at"] = 0

        token = get_shopify_token()

        response = requests.post(
            url,
            headers={
                "X-Shopify-Access-Token": token,
                "Content-Type": "application/json",
            },
            json={
                "query": query,
                "variables": variables or {},
            },
            timeout=25,
        )

    response.raise_for_status()

    data = response.json()

    if data.get("errors"):
        raise RuntimeError(
            f"Shopify GraphQL error: "
            f"{data['errors']}"
        )

    return data


# ============================================================
# SHOPIFY ORDER FLAGGING
# ============================================================

def hold_order(order_id, reason):
    """
    Adds a safety-review tag and note.

    This does NOT automatically cancel or refund the order.
    It tells you that the order must be manually reviewed.
    """

    mutation = """
    mutation OrderUpdate($input: OrderInput!) {
        orderUpdate(input: $input) {
            order {
                id
                name
                note
                tags
            }
            userErrors {
                field
                message
            }
        }
    }
    """

    note = (
        "PRINTORA SAFETY REVIEW REQUIRED\n\n"
        "This order was automatically flagged by "
        "the Printora Labs screening system.\n\n"
        f"Reason: {reason}\n\n"
        "DO NOT FULFILL until a human has reviewed "
        "the product."
    )

    variables = {
        "input": {
            "id": order_id,
            "tags": [
                "FLAGGED-DANGEROUS",
                "MANUAL-REVIEW"
            ],
            "note": note,
        }
    }

    result = shopify_graphql(
        mutation,
        variables
    )

    payload = (
        result
        .get("data", {})
        .get("orderUpdate", {})
    )

    errors = payload.get(
        "userErrors",
        []
    )

    if errors:
        raise RuntimeError(
            f"Shopify order update errors: "
            f"{errors}"
        )

    return True


# ============================================================
# GET PRODUCT IMAGE
# ============================================================

def get_product_image(product_id):
    """
    Gets the product's featured image from Shopify.

    Image screening is optional. If an image cannot be retrieved,
    the order is still screened using text + AI.
    """

    if not product_id:
        return None

    query = """
    query ProductImage($id: ID!) {
        product(id: $id) {
            id
            title
            featuredImage {
                url
            }
        }
    }
    """

    try:
        result = shopify_graphql(
            query,
            {
                "id": product_id
            }
        )

        product = (
            result
            .get("data", {})
            .get("product")
        )

        if not product:
            return None

        image = product.get(
            "featuredImage"
        )

        if not image:
            return None

        return image.get("url")

    except Exception as error:
        print(
            f"Product image lookup failed: {error}"
        )
        return None


# ============================================================
# AI SCREENING
# ============================================================

def ai_screen_order(items):
    """
    Sends product names and, when available, product images
    to Anthropic.

    The AI is instructed to return JSON only.
    """

    if not ANTHROPIC_KEY:
        return True, (
            "AI screening unavailable; "
            "manual review required"
        )

    product_blocks = []

    image_urls = []

    for item in items:

        title = item.get(
            "title",
            "Unknown product"
        )

        product_id = item.get(
            "product_id"
        )

        image_url = None

        if product_id:
            image_url = get_product_image(
                f"gid://shopify/Product/{product_id}"
            )

        product_blocks.append(
            {
                "title": title,
                "image_available": bool(
                    image_url
                )
            }
        )

        if image_url:
            image_urls.append(
                {
                    "title": title,
                    "url": image_url
                }
            )

    system_prompt = """
You are the safety screening system for Printora Labs 3D.

Your job is to identify products that require HUMAN MANUAL REVIEW.

Flag products involving:
- firearms
- firearm parts
- ammunition
- weapon construction
- explosives
- explosive components
- dangerous weapons
- weapon accessories
- tasers or stun weapons
- pepper spray or similar weapons
- other products whose intended purpose is to harm a person
- illegal drug equipment
- sexually explicit products
- other clearly dangerous or prohibited products

Important:
- Do NOT assume every ordinary household object is dangerous.
- A kitchen utensil or ordinary tool is not automatically a weapon.
- If the intended use is ambiguous, flag it for manual review.
- Misspellings and disguised wording should still be considered.
- Never approve an uncertain product.
- This system flags products for human review; it does not make a final legal determination.

Return ONLY valid JSON:

{
  "flag": true or false,
  "confidence": 0-100,
  "reason": "short explanation"
}
"""

    user_content = [
        {
            "type": "text",
            "text": (
                "Review these products:\n\n"
                + json.dumps(
                    product_blocks,
                    indent=2
                )
            )
        }
    ]

    # Add publicly accessible Shopify images when available
    for image in image_urls:

        try:
            parsed = urlparse(
                image["url"]
            )

            if parsed.scheme not in (
                "http",
                "https"
            ):
                continue

            user_content.append(
                {
                    "type": "text",
                    "text": (
                        f"Product image for: "
                        f"{image['title']}"
                    )
                }
            )

            user_content.append(
                {
                    "type": "image",
                    "source": {
                        "type": "url",
                        "url": image["url"]
                    }
                }
            )

        except Exception:
            continue

    try:

        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_KEY,
                "anthropic-version":
                    "2023-06-01",
                "content-type":
                    "application/json",
            },
            json={
                "model":
                    ANTHROPIC_MODEL,
                "max_tokens":
                    300,
                "system":
                    system_prompt,
                "messages": [
                    {
                        "role": "user",
                        "content":
                            user_content,
                    }
                ],
            },
            timeout=45,
        )

        response.raise_for_status()

        data = response.json()

        content = data.get(
            "content",
            []
        )

        text_parts = []

        for block in content:
            if block.get("type") == "text":
                text_parts.append(
                    block.get("text", "")
                )

        answer = "".join(
            text_parts
        ).strip()

        # Remove accidental markdown fences
        answer = re.sub(
            r"^```json\s*",
            "",
            answer,
            flags=re.IGNORECASE
        )

        answer = re.sub(
            r"\s*```$",
            "",
            answer
        )

        result = json.loads(
            answer
        )

        flagged = bool(
            result.get("flag")
        )

        confidence = result.get(
            "confidence",
            0
        )

        reason = result.get(
            "reason",
            "AI screening result"
        )

        # Never automatically approve an
        # uncertain/high-risk AI result.
        if flagged:
            return True, (
                f"AI flagged product "
                f"(confidence {confidence}%): "
                f"{reason}"
            )

        # Require a reasonably confident clean result.
        if confidence < 85:
            return True, (
                "AI result was not sufficiently "
                "confident for automatic approval"
            )

        return False, (
            f"AI screening passed "
            f"(confidence {confidence}%)"
        )

    except Exception as error:

        # FAIL CLOSED
        return True, (
            f"AI screening error; "
            f"manual review required: {error}"
        )


# ============================================================
# COMPLETE ORDER SCREENING
# ============================================================

def classify_order(order):

    items = order.get(
        "line_items",
        []
    )

    if not items:
        return True, (
            "Order contains no readable line items; "
            "manual review required"
        )

    # --------------------------------------------
    # Layer 1: text normalization + exact matching
    # --------------------------------------------

    for item in items:

        title = item.get(
            "title",
            ""
        )

        match = fuzzy_keyword_match(
            title
        )

        if match:
            return True, match

    # --------------------------------------------
    # Layer 2: suspicious contextual terms
    # --------------------------------------------

    combined_text = " ".join(
        item.get("title", "")
        for item in items
    )

    normalized = normalize_text(
        combined_text
    )

    for term in SUSPICIOUS_TERMS:

        if normalize_text(term) in normalized:
            return True, (
                f"Suspicious context term: {term}"
            )

    # --------------------------------------------
    # Layer 3: AI + image screening
    # --------------------------------------------

    return ai_screen_order(
        items
    )


# ============================================================
# EMAIL ALERT
# ============================================================

def alert_you(order, reason):

    if not RESEND_KEY:
        print(
            "Email alert skipped: "
            "RESEND_KEY is missing."
        )
        return False

    if not ALERT_EMAIL:
        print(
            "Email alert skipped: "
            "ALERT_EMAIL is missing."
        )
        return False

    resend.api_key = RESEND_KEY

    items = [
        item.get(
            "title",
            "Unknown"
        )
        for item in order.get(
            "line_items",
            []
        )
    ]

    order_number = order.get(
        "order_number",
        order.get(
            "name",
            "Unknown"
        )
    )

    customer_email = order.get(
        "email",
        "Unknown"
    )

    html = f"""
    <html>
        <body>
            <h2>🚨 Printora Labs Order Flagged</h2>

            <p>
                A new order requires manual safety review.
            </p>

            <hr>

            <p>
                <strong>Order:</strong>
                #{order_number}
            </p>

            <p>
                <strong>Reason:</strong>
                {reason}
            </p>

            <p>
                <strong>Products:</strong>
                {", ".join(items)}
            </p>

            <p>
                <strong>Customer:</strong>
                {customer_email}
            </p>

            <hr>

            <p>
                <strong>
                    FLAGGED-DANGEROUS
                </strong>
            </p>

            <p>
                Do not fulfill this order until it has
                been manually reviewed.
            </p>
        </body>
    </html>
    """

    try:

        email = resend.Emails.send(
            {
                "from":
                    RESEND_FROM,
                "to":
                    [ALERT_EMAIL],
                "subject":
                    (
                        "🚨 Printora order "
                        f"#{order_number} "
                        "requires review"
                    ),
                "html":
                    html,
            }
        )

        print(
            f"Alert email sent successfully: "
            f"{email}"
        )

        return True

    except Exception as error:

        print(
            f"Alert email error: {error}"
        )

        return False


# ============================================================
# WEBHOOK SECURITY
# ============================================================

def verify_shopify_hmac(raw_body):

    if not SHOPIFY_CLIENT_SECRET:
        print(
            "Webhook rejected: "
            "SHOPIFY_CLIENT_SECRET is not configured."
        )
        return False

    provided = request.headers.get(
        "X-Shopify-Hmac-Sha256",
        ""
    )

    if not provided:
        return False

    computed = base64.b64encode(
        hmac.new(
            SHOPIFY_CLIENT_SECRET.encode(
                "utf-8"
            ),
            raw_body,
            hashlib.sha256
        ).digest()
    ).decode(
        "utf-8"
    )

    return hmac.compare_digest(
        provided,
        computed
    )


# ============================================================
# DUPLICATE WEBHOOK PROTECTION
# ============================================================

def is_duplicate_webhook(webhook_id):

    if not webhook_id:
        return False

    with processed_lock:

        if webhook_id in processed_webhooks:
            return True

        processed_webhooks.add(
            webhook_id
        )

        # Keep memory bounded
        if len(processed_webhooks) > 5000:
            processed_webhooks.clear()

    return False


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/", methods=["GET"])
def home():

    return (
        "Printora Labs Order Screening Bot "
        "is running!",
        200
    )


# ============================================================
# SHOPIFY WEBHOOK
# ============================================================

@app.route(
    "/api/webhook",
    methods=["POST"]
)
def handle_order():

    raw_body = request.get_data(
        cache=False
    )

    # --------------------------------------------
    # SECURITY: verify Shopify HMAC
    # --------------------------------------------

    if not verify_shopify_hmac(
        raw_body
    ):
        print(
            "Rejected webhook: invalid HMAC."
        )

        return (
            "Unauthorized",
            401
        )

    topic = request.headers.get(
        "X-Shopify-Topic",
        ""
    )

    webhook_id = request.headers.get(
        "X-Shopify-Webhook-Id",
        ""
    )

    shop_domain = request.headers.get(
        "X-Shopify-Shop-Domain",
        ""
    )

    print(
        f"Received Shopify webhook: "
        f"{topic} | "
        f"{shop_domain} | "
        f"{webhook_id}"
    )

    # --------------------------------------------
    # Only process order creation
    # --------------------------------------------

    if topic != "orders/create":
        return "", 200

    # --------------------------------------------
    # Duplicate protection
    # --------------------------------------------

    if is_duplicate_webhook(
        webhook_id
    ):
        print(
            f"Duplicate webhook ignored: "
            f"{webhook_id}"
        )

        return "", 200

    # --------------------------------------------
    # Parse JSON
    # --------------------------------------------

    try:

        order = json.loads(
            raw_body
        )

    except Exception as error:

        print(
            f"Invalid JSON webhook: {error}"
        )

        return (
            "Invalid JSON",
            400
        )

    order_id = order.get(
        "admin_graphql_api_id"
    )

    # Older payload compatibility
    if not order_id:

        numeric_id = order.get(
            "id"
        )

        if numeric_id:
            order_id = (
                "gid://shopify/Order/"
                f"{numeric_id}"
            )

    if not order_id:

        print(
            "Webhook order has no ID."
        )

        return (
            "Missing order ID",
            400
        )

    print(
        f"Screening Shopify order: "
        f"{order_id}"
    )

    # --------------------------------------------
    # SCREEN ORDER
    # --------------------------------------------

    flagged, reason = classify_order(
        order
    )

    # --------------------------------------------
    # FLAGGED
    # --------------------------------------------

    if flagged:

        print(
            f"⚠️ ORDER FLAGGED: "
            f"{order_id} | {reason}"
        )

        # Update Shopify
        try:

            hold_order(
                order_id,
                reason
            )

            print(
                "Shopify order updated "
                "successfully."
            )

        except Exception as error:

            print(
                f"Shopify order update failed: "
                f"{error}"
            )

        # Email alert
        email_success = alert_you(
            order,
            reason
        )

        if email_success:
            print(
                "Alert email sent successfully."
            )
        else:
            print(
                "Alert email failed."
            )

    # --------------------------------------------
    # APPROVED
    # --------------------------------------------

    else:

        print(
            f"✅ ORDER APPROVED: "
            f"{order_id}"
        )

    return "", 200


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        )
    )
