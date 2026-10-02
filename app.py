import os
import re
import resend
from flask import Flask, request

app = Flask(__name__)

# ============================================================
# CONFIG
# ============================================================

ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "").strip()
RESEND_KEY = os.environ.get("RESEND_KEY", "").strip()

# ============================================================
# TERMS THAT REQUIRE MANUAL REVIEW
# ============================================================

PROHIBITED_TERMS = {
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

    "ammunition",
    "ammo",
    "bullet",
    "bullets",
    "cartridge",
    "cartridges",

    "bomb",
    "bombs",
    "grenade",
    "grenades",
    "explosive",
    "explosives",
    "detonator",
    "detonators",

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

    "taser",
    "tasers",
    "stun gun",
    "stungun",
    "stun guns",
    "stunguns",

    "pepper spray",
    "pepperspray",

    "silencer",
    "suppressor",
    "suppressors",

    "weapon",
    "weapons",
    "tactical",
    "combat",
    "ballistic",
    "armory",
    "arsenal",

    "drug equipment",
    "drug paraphernalia",
}


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def normalize_text(text):
    text = str(text or "").lower()

    text = text.translate(
        str.maketrans({
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
    )

    text = re.sub(
        r"[^a-z0-9]+",
        " ",
        text
    )

    text = re.sub(
        r"\s+",
        " ",
        text
    ).strip()

    return text


def find_prohibited_term(text):
    normalized = normalize_text(text)

    for term in PROHIBITED_TERMS:
        normalized_term = normalize_text(term)

        pattern = (
            r"(?<![a-z0-9])"
            + re.escape(normalized_term)
            + r"(?![a-z0-9])"
        )

        if re.search(pattern, normalized):
            return term

    return None


# ============================================================
# SCREEN ORDER
# ============================================================

def screen_order(order):
    items = order.get("line_items", [])

    for item in items:
        title = item.get("title", "")

        prohibited = find_prohibited_term(title)

        if prohibited:
            return (
                True,
                title,
                prohibited
            )

    return (
        False,
        None,
        None
    )


# ============================================================
# SEND EMAIL
# ============================================================

def send_alert(order, product, prohibited_term):

    if not RESEND_KEY:
        print("RESEND_KEY is missing.")
        return

    if not ALERT_EMAIL:
        print("ALERT_EMAIL is missing.")
        return

    resend.api_key = RESEND_KEY

    order_number = order.get(
        "order_number",
        order.get("name", "Unknown")
    )

    customer_email = order.get(
        "email",
        "Unknown"
    )

    subject = (
        f"⚠️ Printora Order #{order_number} "
        "Requires Manual Review"
    )

    html = f"""
    <html>
    <body>

        <h2>⚠️ Printora Labs Order Flagged</h2>

        <p>
            Your order-screening system detected
            a potentially prohibited item.
        </p>

        <hr>

        <p>
            <strong>Order:</strong>
            #{order_number}
        </p>

        <p>
            <strong>Product:</strong>
            {product}
        </p>

        <p>
            <strong>Detected term:</strong>
            {prohibited_term}
        </p>

        <p>
            <strong>Customer:</strong>
            {customer_email}
        </p>

        <hr>

        <p>
            <strong>ACTION REQUIRED:</strong>
            Do not fulfill this order until
            it has been manually reviewed.
        </p>

    </body>
    </html>
    """

    try:

        resend.Emails.send({
            "from": "onboarding@resend.dev",
            "to": [ALERT_EMAIL],
            "subject": subject,
            "html": html,
        })

        print("Alert email sent successfully.")

    except Exception as error:
        print(f"Email error: {error}")


# ============================================================
# SHOPIFY WEBHOOK
# ============================================================

@app.route(
    "/api/webhook",
    methods=["POST"]
)
def webhook():

    order = request.get_json(
        silent=True
    )

    if not order:
        return "Invalid order", 400

    flagged, product, prohibited_term = screen_order(
        order
    )

    if flagged:

        print(
            f"⚠️ ORDER FLAGGED: {product} "
            f"| detected: {prohibited_term}"
        )

        # Add manual-review tags to the Shopify order
        tags = order.get("tags", "")

        if tags:
            tags += ", "

        tags += "MANUAL-REVIEW, FLAGGED-DANGEROUS"

        # Send you the email
        send_alert(
            order,
            product,
            prohibited_term
        )

        return "Order flagged for manual review", 200

    print("Order passed screening.")

    return "Order passed screening", 200


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/", methods=["GET"])
def home():
    return "Printora Labs Order Screening Bot is running!", 200


# ============================================================
# START
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
