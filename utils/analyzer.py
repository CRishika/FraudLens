import re
from urllib.parse import urlparse


# =========================================================
# MESSAGE / EMAIL ANALYZER
# =========================================================

def analyze_text(text):

    text_lower = text.lower()

    scam_keywords = [
        "urgent",
        "otp",
        "verify your account",
        "click here",
        "claim your prize",
        "winner",
        "lottery",
        "bank account",
        "blocked",
        "suspended",
        "password",
        "upi",
        "refund",
        "kyc",
        "limited time",
        "verify",
        "login",
        "payment",
        "account",
        "prize",
        "immediately",
        "act now",
        "pin",
        "cvv",
        "transaction",
        "cashback",
        "reward",
        "offer",
        "gift",
        "delivery",
        "parcel",
        "income tax",
        "electricity",
        "credit card",
        "debit card",
        "job offer",
        "investment",
        "crypto",
        "loan",
        "fee",
    ]

    found_keywords = [
        keyword
        for keyword in scam_keywords
        if keyword in text_lower
    ]

    found_keywords = list(
        dict.fromkeys(found_keywords)
    )

    score = 0

    # Keyword score
    score += len(
        found_keywords
    ) * 8

    # Numbers
    if re.search(
        r"\b\d{4,8}\b",
        text
    ):
        score += 10

    # Links
    if (
        "http://" in text_lower
        or "https://" in text_lower
        or "www." in text_lower
    ):
        score += 20

    # Sensitive information
    if any(
        word in text_lower
        for word in [
            "otp",
            "password",
            "pin",
            "cvv"
        ]
    ):
        score += 10

    # Urgency
    if any(
        word in text_lower
        for word in [
            "urgent",
            "immediately",
            "limited time",
            "act now",
            "today",
            "within 24 hours"
        ]
    ):
        score += 10

    # Money
    if any(
        word in text_lower
        for word in [
            "money",
            "payment",
            "refund",
            "reward",
            "cashback",
            "prize",
            "fee"
        ]
    ):
        score += 10

    score = min(
        score,
        100
    )

    if score >= 50:

        risk = "HIGH"

    elif score >= 20:

        risk = "MEDIUM"

    else:

        risk = "LOW"

    # =====================================================
    # CATEGORIES
    # =====================================================

    categories = []

    if any(
        word in text_lower
        for word in [
            "bank",
            "bank account",
            "blocked",
            "suspended",
            "credit card",
            "debit card"
        ]
    ):
        categories.append(
            "Banking Scam"
        )

    if any(
        word in text_lower
        for word in [
            "otp",
            "verify",
            "verification"
        ]
    ):
        categories.append(
            "OTP / Verification Scam"
        )

    if any(
        word in text_lower
        for word in [
            "upi",
            "payment",
            "refund",
            "transaction",
            "cashback"
        ]
    ):
        categories.append(
            "UPI / Payment Scam"
        )

    if any(
        word in text_lower
        for word in [
            "winner",
            "lottery",
            "prize",
            "claim your prize",
            "reward",
            "gift"
        ]
    ):
        categories.append(
            "Prize / Lottery Scam"
        )

    if any(
        word in text_lower
        for word in [
            "password",
            "login",
            "account",
            "click here"
        ]
    ):
        categories.append(
            "Phishing Scam"
        )

    if any(
        word in text_lower
        for word in [
            "job offer",
            "work from home",
            "income",
            "salary"
        ]
    ):
        categories.append(
            "Job Scam"
        )

    if any(
        word in text_lower
        for word in [
            "investment",
            "crypto",
            "profit",
            "trading"
        ]
    ):
        categories.append(
            "Investment Scam"
        )

    if any(
        word in text_lower
        for word in [
            "loan",
            "processing fee"
        ]
    ):
        categories.append(
            "Loan Scam"
        )

    if any(
        word in text_lower
        for word in [
            "parcel",
            "delivery",
            "package"
        ]
    ):
        categories.append(
            "Delivery Scam"
        )

    if (
        "http://" in text_lower
        or "https://" in text_lower
        or "www." in text_lower
    ):
        categories.append(
            "Suspicious Link"
        )

    if not categories:

        categories.append(
            "General Suspicious Message"
        )

    return {
        "risk": risk,
        "score": score,
        "keywords": found_keywords,
        "categories": list(
            dict.fromkeys(categories)
        )
    }


# =========================================================
# URL ANALYZER
# =========================================================

def analyze_url(url):

    try:

        url = url.strip()

        parsed = urlparse(
            url
        )

        if (
            parsed.scheme
            not in ["http", "https"]
            or not parsed.netloc
        ):

            return {
                "risk": "HIGH",
                "score": 80,
                "reason":
                    "Invalid or suspicious URL format.",
                "category":
                    "Suspicious URL",
                "categories": [
                    "Suspicious URL"
                ],
                "keywords": []
            }

        domain = parsed.netloc.lower()

        suspicious_words = [
            "login",
            "verify",
            "secure",
            "update",
            "account",
            "free",
            "winner",
            "claim",
            "password",
            "payment",
            "confirm",
            "bank",
            "gift",
            "reward"
        ]

        found = [
            word
            for word in suspicious_words
            if word in domain
        ]

        score = len(
            found
        ) * 15

        warnings = []

        # HTTPS
        if parsed.scheme != "https":

            score += 15

            warnings.append(
                "The URL does not use HTTPS."
            )

        # @ symbol
        if "@" in url:

            score += 30

            warnings.append(
                "The URL contains an @ symbol."
            )

        # Hyphen
        if "-" in domain:

            score += 5

            warnings.append(
                "The domain contains multiple hyphen patterns."
            )

        # IP address
        if re.match(
            r"^\d{1,3}(\.\d{1,3}){3}$",
            parsed.hostname or ""
        ):

            score += 25

            warnings.append(
                "The URL uses an IP address instead of a domain name."
            )

        # Very long URL
        if len(url) > 100:

            score += 10

            warnings.append(
                "The URL is unusually long."
            )

        # Suspicious words
        if found:

            warnings.append(
                "Suspicious words detected: "
                + ", ".join(found)
                + "."
            )

        score = min(
            score,
            100
        )

        if score >= 50:

            risk = "HIGH"

        elif score >= 20:

            risk = "MEDIUM"

        else:

            risk = "LOW"

        if warnings:

            reason = " ".join(
                warnings
            )

        else:

            reason = (
                "No obvious suspicious pattern "
                "was detected. This does not "
                "guarantee that the website is safe."
            )

        categories = [
            "Phishing / Suspicious URL"
        ]

        return {
            "risk": risk,
            "score": score,
            "reason": reason,
            "category":
                "Phishing / Suspicious URL",
            "categories":
                categories,
            "keywords":
                found
        }

    except Exception:

        return {
            "risk": "HIGH",
            "score": 80,
            "reason":
                "Unable to analyze the URL.",
            "category":
                "Suspicious URL",
            "categories": [
                "Suspicious URL"
            ],
            "keywords": []
        }


# =========================================================
# PHONE NUMBER ANALYZER
# =========================================================

def analyze_phone(phone):

    digits = re.sub(
        r"\D",
        "",
        phone
    )

    if len(digits) < 10:

        return {
            "risk": "UNKNOWN",
            "score": 0,
            "reason":
                "Invalid phone number format.",
            "category":
                "Invalid Number",
            "categories": [
                "Invalid Number"
            ],
            "keywords": []
        }

    score = 0

    warnings = []

    # All same digits
    if len(
        set(digits)
    ) == 1:

        score += 40

        warnings.append(
            "The number contains repeated digits."
        )

    # Sequential
    if digits in [
        "1234567890",
        "0123456789",
        "9876543210"
    ]:

        score += 40

        warnings.append(
            "The number follows a sequential pattern."
        )

    # Repeated pairs
    if len(digits) >= 10:

        if len(
            set(
                digits[i:i+2]
                for i in range(
                    0,
                    len(digits) - 1,
                    2
                )
            )
        ) == 1:

            score += 20

            warnings.append(
                "The number contains a repeated pattern."
            )

    score = min(
        score,
        100
    )

    if score >= 50:

        risk = "HIGH"

    elif score >= 20:

        risk = "MEDIUM"

    else:

        risk = "LOW"

    reason = (
        "Pattern-based assessment only. "
        "A phone number cannot be confirmed "
        "as a scam using pattern analysis alone."
    )

    if warnings:

        reason += " " + " ".join(
            warnings
        )

    return {
        "risk": risk,
        "score": score,
        "reason": reason,
        "category":
            "Suspicious Phone Number",
        "categories": [
            "Suspicious Phone Number"
        ],
        "keywords": []
    }