from urllib.parse import urlparse
import ipaddress, re

SHORTENERS={"bit.ly","tinyurl.com","t.co","goo.gl","is.gd","ow.ly","buff.ly"}

def detect_phishing(url):
    p=urlparse(url)
    host=(p.hostname or "").lower()
    path=(p.path or "").lower()
    query=(p.query or "").lower()
    score=0
    reasons=[]

    if p.scheme != "https":
        score += 15; reasons.append("The URL does not use HTTPS.")
    try:
        ipaddress.ip_address(host)
        score += 25; reasons.append("The hostname is an IP address.")
    except ValueError:
        pass
    if "@" in url:
        score += 20; reasons.append("The URL contains '@', which can hide the real destination.")
    if len(url) > 100:
        score += 10; reasons.append("The URL is unusually long.")
    if host.count("-") >= 2:
        score += 10; reasons.append("The hostname contains several hyphens.")
    if host in SHORTENERS:
        score += 20; reasons.append("A URL-shortening service is being used.")
    suspicious_words=("login","verify","verification","account","update","secure","password","banking","signin","confirm")
    hits=[w for w in suspicious_words if w in host or w in path or w in query]
    if len(hits)>=2:
        score += 20; reasons.append("The URL contains multiple sensitive/action words: "+", ".join(sorted(set(hits)))+".")
    if re.search(r"(free|winner|claim|urgent|gift|bonus)", host+path+query):
        score += 10; reasons.append("The URL contains words commonly used in suspicious lures.")

    score=min(score,100)
    if score >= 50:
        result="Phishing"
    elif score >= 25:
        result="Suspicious"
    else:
        result="Safe"
    if not reasons:
        reasons.append("No common phishing indicators were found by this rule-based checker.")
    return score,result,reasons
