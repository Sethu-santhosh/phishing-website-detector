import json
import re
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def get_domain(url):
    """
    Extract the hostname/domain from a submitted URL.
    """

    try:
        url = url.strip()

        if not url:
            return None

        # Add scheme if the user did not enter one
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
            url = "http://" + url

        parsed = urlparse(url)

        domain = parsed.hostname

        if not domain:
            return None

        domain = domain.lower().strip(".")

        return domain

    except Exception:
        return None


# ============================================================
# RDAP REQUEST
# ============================================================

def request_rdap(domain, server):
    """
    Request RDAP information for a domain.

    Returns:
        dict     -> RDAP JSON data
        None     -> if request fails
    """

    try:
        url = f"{server.rstrip('/')}/domain/{domain}"

        request = Request(
            url,
            headers={
                "User-Agent": "PhishGuard/1.0",
                "Accept": "application/rdap+json, application/json",
            },
        )

        with urlopen(request, timeout=10) as response:

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
# FIND REGISTRATION DATE
# ============================================================

def find_registration_date(data):
    """
    Find the original domain registration date
    from an RDAP response.

    RDAP normally stores this in:

        events
            eventAction = registration
            eventDate = ...

    Returns:
        datetime -> registration date
        None     -> not found
    """

    if not isinstance(data, dict):
        return None

    # --------------------------------------------------------
    # First: check the main domain object
    # --------------------------------------------------------

    events = data.get("events", [])

    if isinstance(events, list):

        for event in events:

            if not isinstance(event, dict):
                continue

            action = str(
                event.get("eventAction", "")
            ).lower().strip()

            if action == "registration":

                date_value = event.get("eventDate")

                if date_value:

                    parsed_date = parse_date(
                        date_value
                    )

                    if parsed_date:
                        return parsed_date

    # --------------------------------------------------------
    # Some RDAP responses may contain registration events
    # inside nested entities.
    # --------------------------------------------------------

    entities = data.get("entities", [])

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

                    if date_value:

                        parsed_date = parse_date(
                            date_value
                        )

                        if parsed_date:
                            return parsed_date

    return None


# ============================================================
# DATE PARSER
# ============================================================

def parse_date(date_value):
    """
    Convert common RDAP date formats into a datetime.
    """

    if not date_value:
        return None

    try:

        date_string = str(
            date_value
        ).strip()

        # Handle UTC Z format
        if date_string.endswith("Z"):
            date_string = (
                date_string[:-1] + "+00:00"
            )

        # ISO 8601
        parsed = datetime.fromisoformat(
            date_string
        )

        # Make timezone-aware if necessary
        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=timezone.utc
            )

        return parsed

    except Exception:
        pass

    # Try common fallback formats
    formats = [
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
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
# CALCULATE WEBSITE AGE
# ============================================================

def calculate_age(registration_date):
    """
    Calculate approximate website/domain age.

    Returns:
        string such as:
        '10 years, 4 months'
        '8 months, 12 days'
        '18 days'
    """

    if not registration_date:
        return None

    try:

        now = datetime.now(timezone.utc)

        if registration_date > now:
            return None

        total_days = (
            now - registration_date
        ).days

        # Very new domain
        if total_days < 30:
            return f"{total_days} days"

        # Calculate years/months approximately
        years = now.year - registration_date.year

        months = now.month - registration_date.month

        if now.day < registration_date.day:
            months -= 1

        if months < 0:
            years -= 1
            months += 12

        # If less than one year
        if years == 0:

            if months == 0:
                return f"{total_days} days"

            return f"{months} months"

        # Years only
        if months == 0:
            return f"{years} years"

        # Years + months
        return f"{years} years, {months} months"

    except Exception:
        return None


# ============================================================
# WEBSITE AGE LOOKUP
# ============================================================

def get_website_age(url):
    """
    Find domain registration date and calculate website age.

    Multiple RDAP services are tried so that one unavailable
    service does not immediately cause the feature to fail.

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
    # Do not perform RDAP lookup on an IP address.
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

    # --------------------------------------------------------
    # RDAP servers
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # No registration information available
    # --------------------------------------------------------

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

    # --------------------------------------------------------
    # Website age
    # --------------------------------------------------------

    age_text, registration_date, registration_datetime = (
        get_website_age(url)
    )

    # --------------------------------------------------------
    # URL parsing
    # --------------------------------------------------------

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
    # RULE 1 - HTTP instead of HTTPS
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

            socket.inet_aton(hostname)

            score += 25

            reasons.append(
                "Website uses an IP address instead of a normal domain name."
            )

        except OSError:
            pass

    # ========================================================
    # RULE 3 - @ SYMBOL
    # ========================================================

    if "@" in url:

        score += 20

        reasons.append(
            "URL contains an @ symbol, which can hide the real destination."
        )

    # ========================================================
    # RULE 4 - VERY LONG URL
    # ========================================================

    if len(url) > 100:

        score += 10

        reasons.append(
            "URL is unusually long."
        )

    # ========================================================
    # RULE 5 - MULTIPLE HYPHENS
    # ========================================================

    if hostname.count("-") >= 3:

        score += 10

        reasons.append(
            "Domain contains many hyphens."
        )

    # ========================================================
    # RULE 6 - URL SHORTENERS
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
    # RULE 7 - SENSITIVE ACTION WORDS
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
            "URL contains sensitive account or verification-related words."
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
            "URL contains words commonly used in suspicious or misleading offers."
        )

    # ========================================================
    # RULE 9 - NEW DOMAIN
    # ========================================================

    if registration_datetime:

        try:

            now = datetime.now(timezone.utc)

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

    # ========================================================
    # KEEP SCORE BETWEEN 0 AND 100
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
    # RETURN FIVE VALUES
    # ========================================================

    return (
        score,
        label,
        reasons,
        age_text,
        registration_date,
    )
