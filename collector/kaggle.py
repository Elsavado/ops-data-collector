"""Kaggle datasets with open licences. Listing is anonymous; downloads need KAGGLE_USERNAME / KAGGLE_KEY."""
import os
import time

from .common import get, safe, session
from .public import BIZ, CLOUD, HOSP, ITSM, PHYS, STD, TI, _download, meta_note
from .techdocs import TECH

SEARCHES = {
    TI: ["intrusion detection", "network intrusion", "cyber attack", "malware", "phishing", "ransomware",
         "network traffic", "botnet", "ddos", "threat intelligence", "vulnerability", "cve", "honeypot",
         "security logs", "siem", "insider threat", "fraud detection"],
    STD: ["data breach", "cybersecurity compliance", "gdpr", "security policy"],
    ITSM: ["it service management", "helpdesk tickets", "it support tickets", "incident tickets", "servicenow",
           "itsm", "customer support tickets", "work orders", "predictive maintenance", "asset management"],
    PHYS: ["cctv", "video surveillance", "surveillance camera", "anomaly detection video", "access control",
           "crime", "security guard", "person detection", "face mask detection", "weapon detection",
           "fire detection", "smoke detection", "crowd counting", "license plate", "intrusion video"],
    HOSP: ["hotel bookings", "hotel reviews", "hotel", "cruise ship", "ship ais", "vessel", "port", "airbnb",
           "tourism", "restaurant", "hospitality"],
    CLOUD: ["cloud computing", "server logs", "system logs", "log anomaly", "web server logs", "kubernetes",
            "cloud cost", "cpu utilization", "data center", "network latency", "iot sensors", "telemetry"],
    BIZ: ["it salaries", "tech layoffs", "saas", "it spending", "security companies", "employee attrition",
          "hr analytics", "b2b sales", "crm", "customer churn", "invoices", "accounting"],
    TECH: ["stack overflow survey", "github repositories", "programming languages", "software vulnerabilities",
           "devops", "software bugs", "app reviews", "linux", "docker", "open source", "developer survey",
           "api", "tech stack", "software projects"],
}
OPEN = ("cc0", "cc-by", "cc by", "attribution", "odbl", "open database", "odc", "public domain", "mit",
        "apache", "gpl", "lgpl", "bsd", "community data license", "cdla", "world bank", "us government",
        "open government")


def _ok(lic):
    lic = (lic or "").lower()
    return any(x in lic for x in OPEN) and "noncommercial" not in lic and "nc-" not in lic


def kaggle(sink, st, per_query=3, cap=3 * 2 ** 30):
    user, key = os.environ.get("KAGGLE_USERNAME"), os.environ.get("KAGGLE_KEY")
    if not (user and key):
        print("kaggle: KAGGLE_USERNAME / KAGGLE_KEY not set, skipped")
        return 0
    s = session()
    s.auth = (user, key)
    seen = st.setdefault("kaggle_seen", [])
    seen_set = set(seen)
    pages = st.setdefault("kaggle_page", {})
    n = 0
    for folder, qs in SEARCHES.items():
        for q in qs:
            if sink.full():
                return n
            page = pages.get(q, 1)
            time.sleep(1)
            r = get(s, "https://www.kaggle.com/api/v1/datasets/list",
                    params={"search": q, "sortBy": "votes", "page": page})
            res = r.json() if r else []
            pages[q] = page + 1 if res else 1
            took = 0
            for d in res:
                if took >= per_query or sink.full():
                    break
                ref = d.get("ref", "")
                if not ref or ref in seen_set or not _ok(d.get("licenseName")) or d.get("totalBytes", 0) > cap:
                    continue
                seen.append(ref)
                seen_set.add(ref)
                dest = f"{folder}/Kaggle/{safe(d.get('title') or ref, 80)}"
                time.sleep(1)
                if _download(s, f"https://www.kaggle.com/api/v1/datasets/download/{ref}", cap, sink,
                             f"{dest}/{safe(ref.replace('/', ' - '), 100)}.zip"):
                    meta_note(sink, dest, {"source": "Kaggle", "dataset": f"https://www.kaggle.com/datasets/{ref}",
                                           "title": d.get("title"), "subtitle": d.get("subtitle"),
                                           "license": d.get("licenseName"), "updated": d.get("lastUpdated"),
                                           "votes": d.get("voteCount"), "downloads": d.get("downloadCount"),
                                           "search": q})
                    took += 1
                    n += 1
    return n


SOURCES = {"kaggle": kaggle}
