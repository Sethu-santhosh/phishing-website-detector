import json
import re
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

import whois


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def get_domain(url):
    """
    Extract hostname/domain from the submitted URL.
    """

    try:
        url = url.strip()

        if not url:
            return None

        if not re.match(
            r"^[a-zA-Z][a-zA-Z0-9+.-]*://",
            url
        ):
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
    """
    Convert common date formats into a timezone-aware datetime.
    """

    if not date_value:
        return None

    # WHOIS can sometimes return a list of dates
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
            date_string = (
                date_string[:-1] + "+00:00"
            )

        parsed = datetime.fromisoformat(
            date_string
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

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
# RDAP REQUEST
# ============================================================

def request_rdap(domain, server):
    """
    Request RDAP information.
    """

    try:

        url = (
            f"{server.rstrip('/')}/domain/{domain}"
        )

        request = Request(
            url,
            headers={
                "User-Agent": "PhishGuard/1.0",
                "Accept": (
                    "application/rdap+json, "
                    "application/json"
                ),
            },
        )

        with urlopen(
            request,
            timeout=10
        ) as response:

            if response.status != 200:
                return None

            raw_data = response.read()

            data = json.loads(
                raw_data.decode("utf-8")
            )

            if isinstance(data, dict):
                return data

    except (
        HTTPError,
        URLError,
        TimeoutError,
        socket.timeout,
        json.JSONDecodeError,
        OSError,
        ValueError,
    ):
        pass

    except Exception:
        pass

    return None


# ============================================================
# FIND RDAP REGISTRATION DATE
# ============================================================

def find_registration_date(data):
    """
    Find registration date from RDAP events.
    """

    if not isinstance(data, dict):
        return None

    # Main RDAP events
    events = data.get("events", [])

    if isinstance(events, list):

        for event in events:

            if not isinstance(event, dict):
                continue

            action = str(
                event.get(
                    "eventAction",
                    ""
                )
            ).lower().strip()

            if action == "registration":

                date_value = event.get(
                    "eventDate"
                )

                parsed = parse_date(
                    date_value
                )

                if parsed:
                    return parsed

    # Nested entities
    entities = data.get(
        "entities",
        []
    )

    if isinstance(entities, list):

        for entity in entities:

            if not isinstance(entity, dict):
                continue

            entity_events = entity.get(
                "events",
                []
            )

            if not isinstance(
                entity_events,
                list
            ):
                continue

            for event in entity_events:

                if not isinstance(event, dict):
                    continue

                action = str(
                    event.get(
                        "eventAction",
                        ""
                    )
                ).lower().strip()

                if action == "registration":

                    date_value = event.get(
                        "eventDate"
                    )

                    parsed = parse_date(
                        date_value
                    )

                    if parsed:
                        return parsed

    return None


# ============================================================
# WHOIS FALLBACK
# ============================================================

def get_whois_registration_date(domain):
    """
    WHOIS fallback when RDAP does not provide
    registration information.
    """

    try:

        data = whois.whois(domain)

        if not data:
            return None

        # Most WHOIS servers provide creation_date
        creation_date = getattr(
            data,
            "creation_date",
            None
        )

        if not creation_date:

            # Some implementations behave like dictionaries
            try:
                creation_date = data.get(
                    "creation_date"
                )
            except Exception:
                creation_date = None

        parsed = parse_date(
            creation_date
        )

        return parsed

    except Exception:
        return None


# ============================================================
# CALCULATE WEBSITE AGE
# ============================================================

def calculate_age(registration_date):
    """
    Calculate approximate domain age.
    """

    if not registration_date:
        return None

    try:

        now = datetime.now(
            timezone.utc
        )

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

        return (
            f"{years} years, "
            f"{months} months"
        )

    except Exception:
        return None


# ============================================================
# WEBSITE AGE
# ============================================================

def get_website_age(url):
    """
    Get domain registration information.

    Order:
        1. RDAP
        2. WHOIS
        3. Unavailable

    Returns:
        age_text
        registration_date_text
        registration_datetime
    """

    domain = get_domain(url)

    if not domain:

        return (
            "Unavailable",
            None,
            None,
        )

    # --------------------------------------------------------
    # Skip IP addresses
    # --------------------------------------------------------

    try:

        socket.inet_aton(domain)

        return (
            "Unavailable",
            None,
            None,
        )

    except OSError:
        pass

    # ========================================================
    # METHOD 1 - RDAP
    # ========================================================

    rdap_servers = [
        "https://rdap.org",
        "https://www.rdap.net",
    ]

    for server in rdap_servers:

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

        registration_date_text = (
            registration_date
            .astimezone(timezone.utc)
            .strftime("%Y-%m-%d")
        )

        return (
            age_text,
            registration_date_text,
            registration_date,
        )

    # ========================================================
    # METHOD 2 - WHOIS FALLBACK
    # ========================================================

    registration_date = (
        get_whois_registration_date(domain)
    )

    if registration_date:

        age_text = calculate_age(
            registration_date
        )

        if age_text:

            registration_date_text = (
                registration_date
                .astimezone(timezone.utc)
                .strftime("%Y-%m-%d")
            )

            return (
                age_text,
                registration_date_text,
                registration_date,
            )

    # ========================================================
    # METHOD 3 - UNAVAILABLE
    # ========================================================

    return (
        "Unavailable",
        None,
        None,
    )


# ============================================================
# PHISHING DETECTOR
# ============================================================

def detect_phishing(url):
    """
    Rule-based phishing detection.

    Returns:

        score
        label
        reasons
        age_text
        registration_date
    """

    score = 0

    reasons = []

    url_lower = url.lower().strip()

    # ========================================================
    # WEBSITE AGE
    # ========================================================

    (
        age_text,
        registration_date,
        registration_datetime,
    ) = get_website_age(url)

    # ========================================================
    # URL PARSING
    # ========================================================

    try:

        parsed = urlparse(
            url_lower
            if "://" in url_lower
            else "http://" + url_lower
        )

        hostname = parsed.hostname or ""

    except Exception:

        hostname = ""

    # ========================================================
    # RULE 1 - HTTP
    # ========================================================

    if url_lower.startswith("http://"):

        score += 10

        reasons.append(
            "Website does not use HTTPS."
        )

    # ========================================================
    # RULE 2 - IP ADDRESS
    # ========================================================

    if hostname:

        try:

            socket.inet_aton(
                hostname
            )

            score += 25

            reasons.append(
                "Website uses an IP address "
                "instead of a normal domain name."
            )

        except OSError:
            pass

    # ========================================================
    # RULE 3 - @ SYMBOL
    # ========================================================

    if "@" in url:

        score += 20

        reasons.append(
            "URL contains an @ symbol, "
            "which can hide the real destination."
        )

    # ========================================================
    # RULE 4 - LONG URL
    # ========================================================

    if len(url) > 100:

        score += 10

        reasons.append(
            "URL is unusually long."
        )

    # ========================================================
    # RULE 5 - MANY HYPHENS
    # ========================================================

    if hostname.count("-") >= 3:

        score += 10

        reasons.append(
            "Domain contains many hyphens."
        )

    # ========================================================
    # RULE 6 - URL SHORTENER
    # ========================================================

    shorteners = [
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
    ]

    if hostname in shorteners:

        score += 15

        reasons.append(
            "URL uses a URL shortening service."
        )

    # ========================================================
    # RULE 7 - SENSITIVE WORDS
    # ========================================================

    sensitive_words = [
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
    ]

    found_sensitive = []

    for word in sensitive_words:

        if word in url_lower:
            found_sensitive.append(word)

    if found_sensitive:

        score += min(
            len(found_sensitive) * 5,
            20
        )

        reasons.append(
            "URL contains sensitive account "
            "or verification-related words."
        )

    # ========================================================
    # RULE 8 - SUSPICIOUS LURE WORDS
    # ========================================================

    lure_words = [
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
    ]

    found_lures = []

    for word in lure_words:

        if word in url_lower:
            found_lures.append(word)

    if found_lures:

        score += min(
            len(found_lures) * 5,
            15
        )

        reasons.append(
            "URL contains words commonly used "
            "in suspicious or misleading offers."
        )

    # ========================================================
    # RULE 9 - NEW DOMAIN
    # ========================================================

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
                    f"Domain is very new "
                    f"({age_text} old)."
                )

            elif domain_age_days <= 90:

                score += 10

                reasons.append(
                    f"Domain is relatively new "
                    f"({age_text} old)."
                )

            else:

                reasons.append(
                    f"Domain age: {age_text}."
                )

        except Exception:
            pass

    # ========================================================
    # SCORE LIMIT
    # ========================================================

    score = min(
        max(score, 0),
        100
    )

    # ========================================================
    # RESULT LABEL
    # ========================================================

    if score >= 50:

        label = "Phishing"

    elif score >= 25:

        label = "Suspicious"

    else:

        label = "Safe"

    # ========================================================
    # DEFAULT REASON
    # ========================================================

    if not reasons:

        reasons.append(
            "No major phishing indicators were detected."
        )

    # ========================================================
    # RETURN
    # ========================================================

    return (
        score,
        label,
        reasons,
        age_text,
        registration_date,
    )
