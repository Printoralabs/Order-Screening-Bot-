import os
import requests
from flask import Flask, request

app = Flask(__name__)

# =========================
# ENVIRONMENT VARIABLES
# =========================

SHOPIFY_DOMAIN = os.environ.get("SHOPIFY_DOMAIN")
SHOPIFY_TOKEN = os.environ.get("SHOPIFY_TOKEN")
ANTHROPIC_KEY = os.environ.get("ANTHROPIC_KEY")
ALERT_EMAIL = os.environ.get("ALERT_EMAIL")
RESEND_KEY = os.environ.get("RESEND_KEY")


# =========================
# DANGEROUS PRODUCT KEYWORDS
# =========================

DANGEROUS_KEYWORDS = [
    "knife",
    "knives",
    "gun",
    "firearm",
    "pistol",
    "rifle",
    "ammunition",
    "bullet",
    "explosive",
    "bomb",
    "taser",
    "pepper spray",
    "switchblade",
    "machete",
    "crossbow",
    "brass knuckles",
    "stun gun",
    "grenade",
]


# =========================
# HEALTH CHECK
# =========================

@app.route("/", methods=["GET"])
def home():
    return "Printora Labs Order Screening Bot is running!", 200


# =========================
# ORDER CLASSIFICATION
# =========================

def classify_order(order):
    items = [
        item.get("title", "")
        for item in order.get("line_items", [])
    ]

    # -------------------------
    # Fast keyword screening
    # -------------------------

    for item in items:
        item_lower = item.lower()

        for keyword in DANGEROUS_KEYWORDS:
            if keyword in item_lower:
                return True, f"Keyword match: {item}"

    # -------------------------
    # AI screening
    # -------------------------

    if not ANTHROPIC_KEY:
        return False, "AI screening unavailable"

    prompt = (
        "You are a product safety screening system for a 3D printing "
        "marketplace. Review the following product names.\n\n"
        f"Products: {items}\n\n"
        "Determine whether any product appears to be a weapon, firearm, "
        "ammunition, explosive, dangerous weapon accessory, or another "
        "dangerous item that should be manually reviewed before fulfillment.\n\n"
        "Reply with ONLY YES or NO."
    )

    try:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-5",
                "max_tokens": 10,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
            },
            timeout=25,
        )

        response.raise_for_status()

        data = response.json()

        answer = (
            data.get("content", [{}])[0]
            .get("text", "")
            .strip()
            .upper()
        )

        if answer.startswith("YES"):
            return True, "AI flagged the product as potentially dangerous"

        return False, "AI screening passed"

    except Exception as error:
        # If AI screening fails, do NOT automatically approve
        # the order. Send it for manual review.
        return True, f"AI screening error: {str(error)}"


# =========================
# SHOPIFY ORDER UPDATE
# =========================

def hold_order(order_id, reason):
    if not SHOPIFY_DOMAIN or not SHOPIFY_TOKEN:
        return False

    headers = {
        "X-Shopify-Access-Token": SHOPIFY_TOKEN,
        "Content-Type": "application/json",
    }

    payload = {
        "order": {
            "id": order_id,
            "tags": "FLAGGED-DANGEROUS",
            "note": (
                "AI safety screening flagged this order for manual review.\n\n"
                f"Reason: {reason}\n\n"
                "Do not fulfill until manually reviewed."
            ),
        }
    }

    try:
        response = requests.put(
            f"https://{SHOPIFY_DOMAIN}/admin/api/2024-10/orders/{order_id}.json",
            headers=headers,
            json=payload,
            timeout=15,
        )

        response.raise_for_status()
        return True

    except Exception as error:
        print(f"Shopify update error: {error}")
        return False


# =========================
# EMAIL ALERT
# =========================

def alert_you(order, reason):
    if not RESEND_KEY or not ALERT_EMAIL:
        print("Email alert skipped: missing Resend configuration.")
        return False

    items = [
        item.get("title", "")
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
            <h2>🚨 Printora Labs Order Flagged</h2>

            <p>
                An order has been flagged for manual safety review.
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
                <strong>Items:</strong>
                {", ".join(items)}
            </p>

            <p>
                <strong>Customer:</strong>
                {customer_email}
            </p>

            <hr>

            <p>
                The order has been tagged
                <strong>FLAGGED-DANGEROUS</strong>
                in Shopify.
            </p>

            <p>
                Please manually review the order before fulfilling it.
            </p>
        </body>
    </html>
    """

    try:
        response = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "from": "bot@printoralabs.com",
                "to": [ALERT_EMAIL],
                "subject": f"🚨 Order held for review: #{order_number}",
                "html": html,
            },
            timeout=15,
        )

        response.raise_for_status()
        return True

    except Exception as error:
        print(f"Email alert error: {error}")
        return False


# =========================
# SHOPIFY WEBHOOK
# =========================

@app.route("/api/webhook", methods=["POST"])
def handle_order():

    topic = request.headers.get(
        "X-Shopify-Topic",
        ""
    )

    print(f"Received Shopify webhook: {topic}")

    # Only process new orders
    if topic != "orders/create":
        return "", 200

    order = request.get_json(
        silent=True
    )

    if not order:
        print("Webhook contained no order data.")
        return "", 200

    if "id" not in order:
        print("Webhook order has no ID.")
        return "", 200

    order_id = order["id"]

    print(f"Screening Shopify order: {order_id}")

    # Screen the order
    flagged, reason = classify_order(order)

    if flagged:

        print(
            f"⚠️ ORDER FLAGGED: {order_id} | {reason}"
        )

        # Tag and add note in Shopify
        shopify_success = hold_order(
            order_id,
            reason
        )

        if shopify_success:
            print("Shopify order updated successfully.")
        else:
            print("Shopify order update failed.")

        # Send email notification
        email_success = alert_you(
            order,
            reason
        )

        if email_success:
            print("Alert email sent successfully.")
        else:
            print("Alert email failed.")

    else:

        print(
            f"✅ ORDER APPROVED: {order_id}"
        )

    return "", 200


# =========================
# START APPLICATION
# =========================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get("PORT", 5000)
        )
    )
