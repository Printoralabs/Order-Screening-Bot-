import os
import re
import json
import base64
import hashlib
import hmac
import time
import threading

import requests
import resend
from flask import Flask, request


app = Flask(__name__)


# ============================================================
# CONFIGURATION
# ============================================================

SHOPIFY_DOMAIN = os.environ.get("SHOPIFY_DOMAIN", "").strip()
SHOPIFY_TOKEN = os.environ.get("SHOPIFY_TOKEN", "").strip()
SHOPIFY_CLIENT_ID = os.environ.get("SHOPIFY_CLIENT_ID", "").strip()
SHOPIFY_CLIENT_SECRET = os.environ.get("SHOPIFY_CLIENT_SECRET", "").strip()

ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "").strip()
RESEND_KEY = os.environ.get("RESEND_KEY", "").strip()
RESEND_FROM = os.environ.get(
    "RESEND_FROM",
    "onboarding@resend.dev"
).strip()

# Keep this configurable in Render. Shopify API versions are date-based.
SHOPIFY_API_VERSION = os.environ.get(
    "SHOPIFY_API_VERSION",
    "2026-10"
).strip()


# ============================================================
# STATE
# ============================================================

processed_webhooks = set()
processed_lock = threading.Lock()

shopify_token_cache = {
    "token": None,
    "expires_at": 0
}

shopify_token_lock = threading.Lock()


# ============================================================
# PRINTORA APPROVED PRODUCT ALLOWLIST
# ============================================================
#
# Only products that clearly match this list are automatically
# approved. Everything else goes to manual review.
#
# Prohibited terms are checked FIRST, so an item such as
# "phone stand gun mount" cannot pass just because it contains
# "phone stand".
#

APPROVED_PRODUCT_TERMS = {
    # Organization
    "cable organizer",
    "cable holder",
    "cable clip",
    "cable management",
    "phone stand",
    "tablet stand",
    "desk organizer",
    "desk tray",
    "storage box",
    "storage container",
    "container",
    "drawer organizer",
    "desk accessory",
    "pen holder",
    "pencil holder",

    # Holders / hooks
    "hook",
    "hanger",
    "wall hook",
    "key holder",
    "key hook",
    "tool holder",
    "controller holder",
    "headphone holder",
    "headset holder",
    "phone holder",

    # Shelves / brackets
    "shelf bracket",
    "shelf support",
    "mounting bracket",
    "display stand",
    "display holder",
    "stand",

    # 3D printing accessories
    "filament holder",
    "filament clip",
    "filament guide",
    "spool holder",
    "spool adapter",
    "spool clip",
    "nozzle holder",
    "nozzle stand",
    "3d printer accessory",
    "3d printing accessory",

    # Toys / models
    "toy",
    "figurine",
    "figure",
    "miniature",
    "model",
    "display model",
    "puzzle",
    "game piece",
    "board game accessory",

    # RC / hobby
    "rc car bracket",
    "rc car mount",
    "rc car body",
    "rc car accessory",
    "rc car part",
    "hobby accessory",

    # Electronics / projects
    "electronics enclosure",
    "project enclosure",
    "sensor mount",
    "camera mount",
    "led holder",
    "electronics holder",
    "circuit board enclosure",

    # Household
    "plant pot",
    "planter",
    "flower pot",
    "soap holder",
    "toothbrush holder",
    "bottle holder",
    "cup holder",

    # Decorative
    "decoration",
    "decorative",
    "ornament",
    "wall decoration",
    "desk decoration",
}


# ============================================================
# PROHIBITED / SAFETY REVIEW TERMS
# ============================================================

PROHIBITED_TERMS = {
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
    "revolvers",
    "machine gun",
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
    "brass knuckles",
    "brassknuckles",
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

    # Electrical / chemical weapons
    "taser",
    "tasers",
    "stun gun",
    "stungun",
    "stun guns",
    "stunguns",
    "pepper spray",
    "pepperspray",
    "pepper sprays",
    "peppersprays",

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
    "firearm part",
    "firearm parts",
    "gun part",
    "gun parts",
    "weapon part",
    "weapon parts",

    # Suspicious context
    "weapon",
    "weapons",
    "tactical",
    "combat",
    "ballistic",
    "armory",
    "arsenal",
    "concealed weapon",
    "self defense",
    "self-defense",
    "selfdefense",

    # Drug equipment
    "drug equipment",
    "drug paraphernalia",
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
    if not text:
        return ""

    text = str(text).lower()
    text = text.translate(LEET_TRANSLATION)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^a-z0-9]+", " ", text)
    text = re.sub(r"s+", " ", text).strip()

    return text


def contains_term(text, term):
    """
    Exact normalized word/phrase matching only.
    No fuzzy matching.
    """

    normalized_text = normalize_text(text)
    normalized_term = normalize_text(term)

    if not normalized_text or not normalized_term:
        return False

    pattern = (
        r"(?<![a-z0-9])"
        + re.escape(normalized_term)
        + r"(?![a-z0-9])"
    )

    return re.search(pattern, normalized_text) is not None


def find_prohibited_term(text):
    for term in PROHIBITED_TERMS:
        if contains_term(text, term):
            return term

    return None


def find_approved_term(text):
    for term in APPROVED_PRODUCT_TERMS:
        if contains_term(text, term):
            return term

    return None


# ============================================================
# PRODUCT SCREENING
# ============================================================

def screen_product(title):
    """
    APPROVED:
        Product clearly matches the approved allowlist and
        contains no prohibited term.

    MANUAL REVIEW:
        Product is unknown or contains a prohibited term.
    """

    title = str(title or "").strip()

    if not title:
        return False, "Product has no readable title"

    prohibited = find_prohibited_term(title)

    if prohibited:
        return False, f"Prohibited/safety term detected: {prohibited}"

    approved = find_approved_term(title)

    if approved:
        return True, f"Approved product category: {approved}"

    return False, (
        "Product does not match the Printora approved-product "
        "allowlist"
    )


def classify_order(order):
    """
    Every line item must be clearly approved.

    One unknown or prohibited item causes the entire order
    to require manual review.
    """

    items = order.get("line_items", [])

    if not items:
        return False, (
            "Order contains no readable line items; "
            "manual review required"
        )

    reasons = []

    for item in items:
        title = item.get("title", "").strip()

        approved, reason = screen_product(title)

        if not approved:
            return False, f"{title or 'Unknown product'}: {reason}"

        reasons.append(f"{title}: {reason}")

    return True, "All order items passed the approved-product allowlist"


# ============================================================
# SHOPIFY TOKEN
# ============================================================

def get_shopify_token():
    if SHOPIFY_TOKEN:
        return SHOPIFY_TOKEN

    if not SHOPIFY_DOMAIN:
        raise RuntimeError("SHOPIFY_DOMAIN is not configured")

    if not SHOPIFY_CLIENT_ID:
        raise RuntimeError("SHOPIFY_CLIENT_ID is not configured")

    if not SHOPIFY_CLIENT_SECRET:
        raise RuntimeError("SHOPIFY_CLIENT_SECRET is not configured")

    now = time.time()

    with shopify_token_lock:
        cached_token = shopify_token_cache["token"]
        expires_at = shopify_token_cache["expires_at"]

        if cached_token and expires_at > now + 300:
            return cached_token

        token_url = (
            f"https://{SHOPIFY_DOMAIN}"
            "/admin/oauth/access_token"
        )

        response = requests.post(
            token_url,
            headers={
                "Content-Type": "application/x-www-form-urlencoded"
            },
            data={
                "client_id": SHOPIFY_CLIENT_ID,
                "client_secret": SHOPIFY_CLIENT_SECRET,
                "grant_type": "client_credentials",
            },
            timeout=20,
        )

        response.raise_for_status()

        data = response.json()
        token = data.get("access_token")

        if not token:
            raise RuntimeError(
                "Shopify did not return an access token"
            )

        expires_in = int(data.get("expires_in", 86399))

        shopify_token_cache["token"] = token
        shopify_token_cache["expires_at"] = time.time() + expires_in

        print("Shopify access token refreshed.")

        return token


# ============================================================
# SHOPIFY GRAPHQL
# ============================================================

def shopify_graphql(query, variables=None):
    token = get_shopify_token()

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

    if response.status_code == 401 and not SHOPIFY_TOKEN:
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
            f"Shopify GraphQL error: {data['errors']}"
        )

    return data


# ============================================================
# HOLD ORDER FOR MANUAL REVIEW
# ============================================================

def hold_order(order_id, reason):
    """
    Adds review tags while preserving the order's existing tags.
    Does not cancel or refund the order.
    """

    query = """
    query GetOrderTags($id: ID!) {
        order(id: $id) {
            id
            tags
        }
    }
    """

    existing_result = shopify_graphql(
        query,
        {"id": order_id}
    )

    existing_order = (
        existing_result
        .get("data", {})
        .get("order")
    )

    existing_tags = (
        existing_order.get("tags", [])
        if existing_order
        else []
    )

    tags = list(dict.fromkeys(
        existing_tags
        + [
            "FLAGGED-DANGEROUS",
            "MANUAL-REVIEW",
        ]
    ))

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

    result = shopify_graphql(
        mutation,
        {
            "input": {
                "id": order_id,
                "tags": tags,
                "note": note,
            }
        }
    )

    payload = (
        result
        .get("data", {})
        .get("orderUpdate", {})
    )

    errors = payload.get("userErrors", [])

    if errors:
        raise RuntimeError(
            f"Shopify order update errors: {errors}"
        )

    return True


# ============================================================
# EMAIL ALERT
# ============================================================

def alert_you(order, reason):
    if not RESEND_KEY:
        print(
            "Email alert skipped: RESEND_KEY is missing."
        )
        return False

    if not ALERT_EMAIL:
        print(
            "Email alert skipped: ALERT_EMAIL is missing."
        )
        return False

    resend.api_key = RESEND_KEY

    items = [
        item.get("title", "Unknown")
        for item in order.get("line_items", [])
    ]

    order_number = order.get(
        "order_number",
        order.get("name", "Unknown")
    )

    customer_email = order.get(
        "email",
        "Unknown"
    )

    html = f"""
    <html>
        <body>
            <h2>Printora Labs Order Requires Review</h2>

            <p>
                A new order was automatically sent to manual review.
            </p>

            <hr>

            <p><strong>Order:</strong> #{order_number}</p>

            <p><strong>Reason:</strong> {reason}</p>

            <p>
                <strong>Products:</strong>
                {", ".join(items)}
            </p>

            <p>
                <strong>Customer:</strong>
                {customer_email}
            </p>

            <hr>

            <p><strong>Tags:</strong>
            FLAGGED-DANGEROUS, MANUAL-REVIEW</p>

            <p>
                Do not fulfill this order until it has been
                manually reviewed.
            </p>
        </body>
    </html>
    """

    try:
        email = resend.Emails.send({
            "from": RESEND_FROM,
            "to": [ALERT_EMAIL],
            "subject": (
                f"Printora order #{order_number} "
                "requires manual review"
            ),
            "html": html,
        })

        print(
            f"Alert email sent successfully: {email}"
        )

        return True

    except Exception as error:
        print(
            f"Alert email error: {error}"
        )

        return False


# ============================================================
# SHOPIFY WEBHOOK HMAC
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
            SHOPIFY_CLIENT_SECRET.encode("utf-8"),
            raw_body,
            hashlib.sha256
        ).digest()
    ).decode("utf-8")

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

        processed_webhooks.add(webhook_id)

        if len(processed_webhooks) > 5000:
            processed_webhooks.clear()

    return False


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/", methods=["GET"])
def home():
    return (
        "Printora Labs Order Screening Bot is running!",
        200
    )


# ============================================================
# SHOPIFY WEBHOOK
# ============================================================

@app.route("/api/webhook", methods=["POST"])
def handle_order():
    # Keep raw bytes for HMAC verification.
    raw_body = request.get_data(cache=False)

    if not verify_shopify_hmac(raw_body):
        print("Rejected webhook: invalid HMAC.")
        return "Unauthorized", 401

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
        f"{topic} | {shop_domain} | {webhook_id}"
    )

    if topic != "orders/create":
        return "", 200

    if is_duplicate_webhook(webhook_id):
        print(
            f"Duplicate webhook ignored: {webhook_id}"
        )
        return "", 200

    try:
        order = json.loads(raw_body)
    except Exception as error:
        print(
            f"Invalid JSON webhook: {error}"
        )
        return "Invalid JSON", 400

    if not isinstance(order, dict):
        return "Invalid JSON", 400

    order_id = order.get(
        "admin_graphql_api_id"
    )

    if not order_id:
        numeric_id = order.get("id")

        if numeric_id:
            order_id = (
                "gid://shopify/Order/"
                f"{numeric_id}"
            )

    if not order_id:
        print("Webhook order has no ID.")
        return "Missing order ID", 400

    print(
        f"Screening Shopify order: {order_id}"
    )

    # Fail closed: an exception means manual review.
    try:
        approved, reason = classify_order(order)
    except Exception as error:
        approved = False
        reason = (
            "Screening error; manual review required: "
            f"{error}"
        )

    if approved:
        print(
            f"ORDER APPROVED: {order_id} | {reason}"
        )
        return "", 200

    print(
        f"ORDER MANUAL REVIEW: "
        f"{order_id} | {reason}"
    )

    try:
        hold_order(
            order_id,
            reason
        )

        print(
            "Shopify order tagged for manual review."
        )

    except Exception as error:
        print(
            f"Shopify order update failed: {error}"
        )

    alert_you(
        order,
        reason
    )

    # Return 200 so Shopify does not repeatedly retry an
    # already-processed manual-review order.
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
