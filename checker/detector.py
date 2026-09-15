import json
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

import whois


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def get_domain(url):
    try:
        url = url.strip()

        if not url:
            return None

        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
            url = "http://" + url

        parsed = urlparse(url)
        domain = parsed.hostname

        if not domain:
            return None

        return domain.lower().strip(".")

    except Exception:
        return None


# ============================================================
# DATE PARSER
# ============================================================

def parse_date(date_value):

    if not date_value:
        return None

    if isinstance(date_value, (list, tuple)):

        valid_dates = []

        for item in date_value:
            parsed = parse_date(item)

            if parsed:
                valid_dates.append(parsed)

        if valid_dates:
            return min(valid_dates)

        return None

    try:

        date_string = str(date_value).strip()

        if date_string.endswith("Z"):
            date_string = date_string[:-1] + "+00:00"

        parsed = datetime.fromisoformat(date_string)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed

    except Exception:
        pass

    formats = [
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%d-%b-%Y",
        "%d.%m.%Y",
    ]

    for fmt in formats:

        try:

            parsed = datetime.strptime(
                str(date_value),
                fmt
            )

            return parsed.replace(
                tzinfo=timezone.utc
            )

        except ValueError:
            continue

    return None


# ============================================================
# RDAP
# ============================================================

def request_rdap(domain, server):

    try:

        url = f"{server.rstrip('/')}/domain/{domain}"

        request = Request(
            url,
            headers={
                "User-Agent": "PhishGuard/2.0",
                "Accept": (
                    "application/rdap+json, "
                    "application/json"
                ),
            },
        )

        with urlopen(
            request,
            timeout=8
        ) as response:

            if response.status != 200:
                return None

            data = json.loads(
                response.read().decode("utf-8")
            )

            if isinstance(data, dict):
                return data

    except Exception:
        pass

    return None


def find_registration_date(data):

    if not isinstance(data, dict):
        return None

    events = data.get("events", [])

    if isinstance(events, list):

        for event in events:

            if not isinstance(event, dict):
                continue

            action = str(
                event.get("eventAction", "")
            ).lower().strip()

            if action == "registration":

                parsed = parse_date(
                    event.get("eventDate")
                )

                if parsed:
                    return parsed

    entities = data.get("entities", [])

    if isinstance(entities, list):

        for entity in entities:

            if not isinstance(entity, dict):
                continue

            events = entity.get("events", [])

            if not isinstance(events, list):
                continue

            for event in events:

                if not isinstance(event, dict):
                    continue

                action = str(
                    event.get("eventAction", "")
                ).lower().strip()

                if action == "registration":

                    parsed = parse_date(
                        event.get("eventDate")
                    )

                    if parsed:
                        return parsed

    return None


# ============================================================
# WHOIS FALLBACK
# ============================================================

def get_whois_registration_date(domain):

    try:

        data = whois.whois(domain)

        if not data:
            return None

        creation_date = getattr(
            data,
            "creation_date",
            None
        )

        if not creation_date:

            try:
                creation_date = data.get(
                    "creation_date"
                )
            except Exception:
                creation_date = None

        return parse_date(creation_date)

    except Exception:
        return None


# ============================================================
# DOMAIN AGE
# ============================================================

def calculate_age(registration_date):

    if not registration_date:
        return None

    try:

        now = datetime.now(timezone.utc)

        if registration_date > now:
            return None

        total_days = (
            now - registration_date
        ).days

        if total_days < 30:
            return f"{total_days} days"

        years = (
            now.year -
            registration_date.year
        )

        months = (
            now.month -
            registration_date.month
        )

        if now.day < registration_date.day:
            months -= 1

        if months < 0:
            years -= 1
            months += 12

        if years == 0:

            if months == 0:
                return f"{total_days} days"

            return f"{months} months"

        if months == 0:
            return f"{years} years"

        return f"{years} years, {months} months"

    except Exception:
        return None


def get_website_age(url):

    domain = get_domain(url)

    if not domain:
        return "Unavailable", None, None

    try:

        socket.inet_aton(domain)

        return "Unavailable", None, None

    except OSError:
        pass

    # RDAP
    for server in [
        "https://rdap.org",
        "https://www.rdap.net",
    ]:

        data = request_rdap(
            domain,
            server
        )

        if not data:
            continue

        registration_date = (
            find_registration_date(data)
        )

        if not registration_date:
            continue

        age_text = calculate_age(
            registration_date
        )

        if not age_text:
            continue

        date_text = (
            registration_date
            .astimezone(timezone.utc)
            .strftime("%Y-%m-%d")
        )

        return (
            age_text,
            date_text,
            registration_date,
        )

    # WHOIS fallback
    registration_date = (
        get_whois_registration_date(domain)
    )

    if registration_date:

        age_text = calculate_age(
            registration_date
        )

        if age_text:

            date_text = (
                registration_date
                .astimezone(timezone.utc)
                .strftime("%Y-%m-%d")
            )

            return (
                age_text,
                date_text,
                registration_date,
            )

    return "Unavailable", None, None


# ============================================================
# IP ADDRESS CHECK
# ============================================================

def is_ip_address(hostname):

    if not hostname:
        return False

    try:
        socket.inet_aton(hostname)
        return True
    except OSError:
        return False


# ============================================================
# SUSPICIOUS TLD
# ============================================================

SUSPICIOUS_TLDS = {
    ".online",
    ".site",
    ".top",
    ".xyz",
    ".click",
    ".buzz",
    ".club",
    ".icu",
    ".live",
    ".cam",
    ".cyou",
    ".monster",
}


def has_suspicious_tld(domain):

    if not domain:
        return False

    return any(
        domain.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    )


# ============================================================
# URL SHORTENERS
# ============================================================

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
}


# ============================================================
# SUSPICIOUS WORDS
# ============================================================

SENSITIVE_WORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "account",
    "password",
    "update",
    "secure",
    "security",
    "confirm",
    "confirmation",
    "bank",
    "payment",
    "wallet",
    "credential",
    "authenticate",
}

LURE_WORDS = {
    "free",
    "winner",
    "winning",
    "prize",
    "bonus",
    "gift",
    "offer",
    "urgent",
    "limited",
    "claim",
    "reward",
    "click",
    "scholarship",
    "laptop",
    "giveaway",
}

ACTION_WORDS = {
    "apply",
    "register",
    "submit",
    "download",
    "activate",
    "unlock",
    "access",
}


# ============================================================
# DOMAIN STRUCTURE ANALYSIS
# ============================================================

def analyze_domain_structure(domain):

    score = 0
    reasons = []

    if not domain:
        return score, reasons

    labels = domain.split(".")

    # Too many subdomains
    if len(labels) >= 5:

        score += 10

        reasons.append(
            "Domain contains an unusually large number "
            "of subdomains."
        )

    # Very long domain
    if len(domain) >= 45:

        score += 8

        reasons.append(
            "Domain name is unusually long."
        )

    # Excessive hyphens
    hyphen_count = domain.count("-")

    if hyphen_count >= 3:

        score += 10

        reasons.append(
            "Domain contains multiple hyphens."
        )

    # Repeated separators
    if "--" in domain:

        score += 5

        reasons.append(
            "Domain contains repeated hyphens."
        )

    # Suspicious TLD
    if has_suspicious_tld(domain):

        score += 10

        reasons.append(
            "Domain uses a higher-risk generic TLD."
        )

    # Numeric-heavy domain
    letters = sum(
        char.isalpha()
        for char in domain
    )

    numbers = sum(
        char.isdigit()
        for char in domain
    )

    if numbers >= 4 and numbers > letters:

        score += 8

        reasons.append(
            "Domain contains an unusual amount "
            "of numeric characters."
        )

    return score, reasons


# ============================================================
# BRAND IMPERSONATION CHECK
# ============================================================

COMMON_BRANDS = {
    "paypal",
    "google",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "instagram",
    "whatsapp",
    "netflix",
    "telegram",
    "linkedin",
    "sbi",
    "hdfc",
    "icici",
    "axis",
    "phonepe",
    "paytm",
}


def check_brand_impersonation(domain):

    if not domain:
        return 0, []

    domain_without_tld = domain.rsplit(
        ".",
        1
    )[0]

    for brand in COMMON_BRANDS:

        if brand in domain_without_tld:

            # Exact brand domain is not automatically suspicious.
            if domain_without_tld == brand:
                continue

            return (
                15,
                [
                    f"Domain contains the brand name "
                    f"'{brand}' but is not the exact brand domain."
                ],
            )

    return 0, []


# ============================================================
# SSL/TLS ANALYSIS
# ============================================================

def check_ssl_certificate(domain):

    score = 0
    reasons = []

    if not domain:
        return score, reasons

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (domain, 443),
            timeout=5
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as secure_socket:

                certificate = (
                    secure_socket.getpeercert()
                )

                if not certificate:
                    return score, reasons

                not_after = certificate.get(
                    "notAfter"
                )

                if not_after:

                    expiry = datetime.strptime(
                        not_after,
                        "%b %d %H:%M:%S %Y %Z"
                    ).replace(
                        tzinfo=timezone.utc
                    )

                    now = datetime.now(
                        timezone.utc
                    )

                    if expiry < now:

                        score += 25

                        reasons.append(
                            "SSL certificate appears to be expired."
                        )

                    elif (
                        expiry - now
                    ).days <= 7:

                        score += 5

                        reasons.append(
                            "SSL certificate expires very soon."
                        )

    except Exception:
        pass

    return score, reasons


# ============================================================
# URL CONTENT ANALYSIS
# ============================================================

def analyze_url_words(url):

    score = 0
    reasons = []

    url_lower = url.lower()

    found_sensitive = [
        word
        for word in SENSITIVE_WORDS
        if word in url_lower
    ]

    if found_sensitive:

        points = min(
            len(found_sensitive) * 4,
            16
        )

        score += points

        reasons.append(
            "URL contains account, login, payment, "
            "or verification-related terms."
        )

    found_lures = [
        word
        for word in LURE_WORDS
        if word in url_lower
    ]

    if found_lures:

        points = min(
            len(found_lures) * 5,
            20
        )

        score += points

        reasons.append(
            "URL contains words commonly associated "
            "with suspicious offers or rewards."
        )

    found_actions = [
        word
        for word in ACTION_WORDS
        if word in url_lower
    ]

    if found_actions:

        points = min(
            len(found_actions) * 3,
            9
        )

        score += points

        reasons.append(
            "URL contains action-oriented words "
            "commonly used to lure users."
        )

    return score, reasons


# ============================================================
# MAIN DETECTION ENGINE
# ============================================================

def detect_phishing(url):

    score = 0
    reasons = []

    url = url.strip()

    # --------------------------------------------------------
    # DOMAIN AGE
    # --------------------------------------------------------

    (
        age_text,
        registration_date,
        registration_datetime,
    ) = get_website_age(url)

    # --------------------------------------------------------
    # URL PARSING
    # --------------------------------------------------------

    try:

        parsed = urlparse(
            url.lower()
            if "://" in url.lower()
            else "http://" + url.lower()
        )

        hostname = parsed.hostname or ""

    except Exception:

        hostname = ""

    domain = hostname

    # --------------------------------------------------------
    # INVALID DOMAIN
    # --------------------------------------------------------

    if not domain:

        return (
            100,
            "Phishing",
            ["Unable to identify a valid domain name."],
            age_text,
            registration_date,
        )

    # --------------------------------------------------------
    # HTTP
    # --------------------------------------------------------

    if url.lower().startswith("http://"):

        score += 10

        reasons.append(
            "Website does not use HTTPS."
        )

    # --------------------------------------------------------
    # IP ADDRESS
    # --------------------------------------------------------

    if is_ip_address(hostname):

        score += 30

        reasons.append(
            "Website uses an IP address instead "
            "of a normal domain name."
        )

    # --------------------------------------------------------
    # @ SYMBOL
    # --------------------------------------------------------

    if "@" in url:

        score += 25

        reasons.append(
            "URL contains an @ symbol, which can "
            "hide the actual destination."
        )

    # --------------------------------------------------------
    # LONG URL
    # --------------------------------------------------------

    if len(url) > 100:

        score += 10

        reasons.append(
            "URL is unusually long."
        )

    # --------------------------------------------------------
    # URL SHORTENER
    # --------------------------------------------------------

    if hostname in URL_SHORTENERS:

        score += 15

        reasons.append(
            "URL uses a URL shortening service."
        )

    # --------------------------------------------------------
    # DOMAIN STRUCTURE
    # --------------------------------------------------------

    structure_score, structure_reasons = (
        analyze_domain_structure(domain)
    )

    score += structure_score
    reasons.extend(structure_reasons)

    # --------------------------------------------------------
    # BRAND IMPERSONATION
    # --------------------------------------------------------

    brand_score, brand_reasons = (
        check_brand_impersonation(domain)
    )

    score += brand_score
    reasons.extend(brand_reasons)

    # --------------------------------------------------------
    # SUSPICIOUS WORDS
    # --------------------------------------------------------

    word_score, word_reasons = (
        analyze_url_words(url)
    )

    score += word_score
    reasons.extend(word_reasons)

    # --------------------------------------------------------
    # DOMAIN AGE
    # --------------------------------------------------------

    if registration_datetime:

        try:

            now = datetime.now(
                timezone.utc
            )

            domain_age_days = (
                now - registration_datetime
            ).days

            if domain_age_days <= 30:

                score += 20

                reasons.append(
                    f"Domain is very new ({age_text} old)."
                )

            elif domain_age_days <= 90:

                score += 10

                reasons.append(
                    f"Domain is relatively new ({age_text} old)."
                )

            else:

                reasons.append(
                    f"Domain age: {age_text}."
                )

        except Exception:
            pass

    # --------------------------------------------------------
    # SSL
    # --------------------------------------------------------

    ssl_score, ssl_reasons = (
        check_ssl_certificate(domain)
    )

    score += ssl_score
    reasons.extend(ssl_reasons)

    # --------------------------------------------------------
    # FINAL SCORE
    # --------------------------------------------------------

    score = min(
        max(score, 0),
        100
    )

    # --------------------------------------------------------
    # FINAL CLASSIFICATION
    # --------------------------------------------------------

    if score >= 70:

        label = "Phishing"

    elif score >= 40:

        label = "Suspicious"

    else:

        label = "Safe"

    # --------------------------------------------------------
    # NO REASONS
    # --------------------------------------------------------

    if not reasons:

        reasons.append(
            "No major phishing indicators were detected."
        )

    # Remove duplicate reasons
    reasons = list(dict.fromkeys(reasons))

    # --------------------------------------------------------
    # RETURN
    # --------------------------------------------------------

    return (
        score,
        label,
        reasons,
        age_text,
        registration_date,
    )
