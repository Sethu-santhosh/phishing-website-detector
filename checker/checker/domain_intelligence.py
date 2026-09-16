import socket
import dns.resolver


def get_domain_intelligence(domain):
import socket
import dns.resolver


def get_domain_intelligence(domain):
    result = {
        "domain": domain,
        "resolves": False,
        "ipv4": [],
        "ipv6": [],
        "mx_records": [],
        "nameservers": [],
        "dns_risk": 0,
        "dns_reasons": [],
    }

    if not domain:
        result["dns_risk"] += 20
        result["dns_reasons"].append("Domain could not be extracted.")
        return result

    # DNS / IP resolution
    try:
        addresses = socket.getaddrinfo(
            domain,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
        )

        for item in addresses:
            address = item[4][0]

            if ":" in address:
                if address not in result["ipv6"]:
                    result["ipv6"].append(address)
            else:
                if address not in result["ipv4"]:
                    result["ipv4"].append(address)

        if result["ipv4"] or result["ipv6"]:
            result["resolves"] = True
        else:
            result["dns_risk"] += 25
            result["dns_reasons"].append(
                "Domain does not resolve to an IP address."
            )

    except socket.gaierror:
        result["dns_risk"] += 25
        result["dns_reasons"].append(
            "DNS resolution failed."
        )

    except Exception:
        result["dns_reasons"].append(
            "Unable to complete DNS resolution."
        )

    # MX record
    try:
        answers = dns.resolver.resolve(
            domain,
            "MX",
            lifetime=5,
        )

        for answer in answers:
            result["mx_records"].append(
                str(answer.exchange).rstrip(".")
            )

    except Exception:
        result["dns_reasons"].append(
            "No MX record found."
        )

    # Nameservers
    try:
        answers = dns.resolver.resolve(
            domain,
            "NS",
            lifetime=5,
        )

        for answer in answers:
            nameserver = str(answer.target).rstrip(".")

            if nameserver not in result["nameservers"]:
                result["nameservers"].append(nameserver)

    except Exception:
        result["dns_risk"] += 5
        result["dns_reasons"].append(
            "Nameserver information could not be retrieved."
        )

    if result["resolves"] and not result["nameservers"]:
        result["dns_risk"] += 10
        result["dns_reasons"].append(
            "Domain resolves but nameserver information is unavailable."
        )

    result["dns_risk"] = min(
        result["dns_risk"],
        30,
    )

    return result
