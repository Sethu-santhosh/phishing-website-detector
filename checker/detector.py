import re
import json
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from datetime import datetime, timezone


# =========================================================
# DOMAIN EXTRACTION
# =========================================================

def get_domain(url):
    """Extract domain from URL."""

    try:
        parsed = urlparse(url)

        domain = parsed.netloc.lower()

        if not domain:
            return ""

        # Remove username/password
        if "@" in domain:
            domain = domain.split("@")[-1]

        # Remove port
        domain = domain.split(":")[0]

        return domain

    except Exception:
        return ""


# =========================================================
# RDAP REQUEST
# =========================================================

def request_rdap(domain, server):

    try:

        api_url = f"{server.rstrip('/')}/domain/{domain}"

        request = Request(
            api_url,
            headers={
                "User-Agent": "PhishGuard/1.0"
            }
        )

        with urlopen(request, timeout=8) as response:

            data = response.read().decode("utf-8")

            return json.loads(data)

    except (
        HTTPError,
        URLError,
        TimeoutError,
        ValueError,
        json.JSONDecodeError
    ):

        return None

    except Exception:

        return None


# =========================================================
# FIND REGISTRATION DATE
# =========================================================

def find_registration_date(data):

    if not data:
        return None

    events = data.get("events", [])

    for event in events:

        action = event.get("eventAction", "").lower()

        if action in [
            "registration",
            "registered"
        ]:

            date = event.get("eventDate")

            if date:
                return date

    return None


# =========================================================
# WEBSITE AGE
# =========================================================

def get_website_age(url):

    domain = get_domain(url)

    if not domain:

        return "Unknown", None, None


    # -----------------------------------------------------
    # PRIMARY RDAP SERVER
    # -----------------------------------------------------

    servers = [

        "https://rdap.org",

        "https://www.rdap.net"

    ]


    registration_date = None


    # -----------------------------------------------------
    # TRY SERVERS ONE BY ONE
    # -----------------------------------------------------

    for server in servers:

        data = request_rdap(
            domain,
            server
        )

        registration_date = find_registration_date(
            data
        )

        if registration_date:

            break


    # -----------------------------------------------------
    # NO REGISTRATION INFORMATION
    # -----------------------------------------------------

    if not registration_date:

        return "Unavailable", None, None


    # -----------------------------------------------------
    # CONVERT DATE
    # -----------------------------------------------------

    try:

        clean_date = registration_date.replace(
            "Z",
            "+00:00"
        )

        created = datetime.fromisoformat(
            clean_date
        )

        if created.tzinfo is None:

            created = created.replace(
                tzinfo=timezone.utc
            )

        now = datetime.now(
            timezone.utc
        )

        age_days = max(
            0,
            (now - created).days
        )


    except Exception:

        return "Unavailable", None, None


    # -----------------------------------------------------
    # FORMAT AGE
    # -----------------------------------------------------

    if age_days < 30:

        age_text = f"{age_days} days"


    elif age_days < 365:

        months = age_days // 30

        age_text = f"{months} month(s)"


    else:

        years = age_days // 365

        remaining_days = age_days % 365

        age_text = f"{years} year(s)"

        if remaining_days >= 30:

            remaining_months = remaining_days // 30

            age_text += (
                f", {remaining_months} month(s)"
            )


    formatted_date = created.strftime(
        "%d %B %Y"
    )


    return (
        age_text,
        age_days,
        formatted_date
    )


# =========================================================
# PHISHING DETECTOR
# =========================================================

def detect_phishing(url):

    score = 0

    reasons = []


    url_lower = url.lower()


    # =====================================================
    # HTTPS
    # =====================================================

    if not url_lower.startswith("https://"):

        score += 20

        reasons.append(
            "Website does not use HTTPS."
        )


    # =====================================================
    # IP ADDRESS
    # =====================================================

    try:

        parsed = urlparse(url)

        hostname = parsed.hostname or ""

        ip_pattern = (
            r"^\d{1,3}(\.\d{1,3}){3}$"
        )

        if re.match(
            ip_pattern,
            hostname
        ):

            score += 30

            reasons.append(
                "URL uses an IP address instead of a normal domain name."
            )

    except Exception:

        hostname = ""


    # =====================================================
    # @ SYMBOL
    # =====================================================

    if "@" in url:

        score += 25

        reasons.append(
            "URL contains an @ symbol, which can hide the real destination."
        )


    # =====================================================
    # LONG URL
    # =====================================================

    if len(url) > 100:

        score += 15

        reasons.append(
            "URL is unusually long."
        )


    # =====================================================
    # MANY HYPHENS
    # =====================================================

    if url.count("-") >= 3:

        score += 10

        reasons.append(
            "Domain contains many hyphens."
        )


    # =====================================================
    # URL SHORTENERS
    # =====================================================

    shorteners = [

        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly",
        "ow.ly",
        "buff.ly"

    ]


    if any(
        shortener in url_lower
        for shortener in shorteners
    ):

        score += 20

        reasons.append(
            "URL uses a URL-shortening service."
        )


    # =====================================================
    # SUSPICIOUS WORDS
    # =====================================================

    suspicious_words = [

        "login",
        "signin",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "confirm",
        "password",
        "bank",
        "wallet",
        "payment",
        "bonus",
        "free",
        "gift",
        "claim"

    ]


    found_words = []


    for word in suspicious_words:

        if word in url_lower:

            found_words.append(
                word
            )


    if found_words:

        score += min(
            len(found_words) * 5,
            20
        )

        reasons.append(
            "URL contains suspicious keywords: "
            + ", ".join(found_words)
        )


    # =====================================================
    # WEBSITE AGE
    # =====================================================

    age_text, age_days, registration_date = (
        get_website_age(url)
    )


    # Very new domain
    if age_days is not None:

        if age_days <= 30:

            score += 20

            reasons.append(
                "Domain is very new (registered within the last 30 days)."
            )


        elif age_days <= 90:

            score += 10

            reasons.append(
                "Domain is relatively new (less than 90 days old)."
            )


    # =====================================================
    # LIMIT SCORE
    # =====================================================

    score = min(
        score,
        100
    )


    # =====================================================
    # RESULT
    # =====================================================

    if score >= 50:

        label = "Phishing"


    elif score >= 25:

        label = "Suspicious"


    else:

        label = "Safe"


    # =====================================================
    # NO REASONS
    # =====================================================

    if not reasons:

        reasons.append(
            "No common phishing indicators were detected."
        )


    # =====================================================
    # RETURN
    # =====================================================

    return (
        score,
        label,
        reasons,
        age_text,
        registration_date
    )
