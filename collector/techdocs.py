"""IT & developer tools: product lifecycles, Q&A archives, official documentation, tool catalogues."""
import datetime as dt
import time

from .common import add_sheet, get, new_book, save_book, session
from .public import CLOUD, PUB, _download, meta_note

TECH = f"{PUB}/9 IT & Developer Tools"

SE_SITES = ["serverfault.com", "superuser.com", "security.stackexchange.com", "askubuntu.com",
            "unix.stackexchange.com", "dba.stackexchange.com", "devops.stackexchange.com",
            "networkengineering.stackexchange.com", "softwareengineering.stackexchange.com",
            "codereview.stackexchange.com", "iot.stackexchange.com", "raspberrypi.stackexchange.com",
            "crypto.stackexchange.com", "reverseengineering.stackexchange.com", "sqa.stackexchange.com",
            "sharepoint.stackexchange.com", "salesforce.stackexchange.com", "webapps.stackexchange.com",
            "apple.stackexchange.com", "android.stackexchange.com", "datascience.stackexchange.com",
            "ai.stackexchange.com", "cs.stackexchange.com", "stats.stackexchange.com"]

# (folder, title, url, file name, licence)
DOCS = [
    ("Official documentation", "Kubernetes documentation", "https://github.com/kubernetes/website/archive/HEAD.zip",
     "kubernetes-website.zip", "CC BY 4.0"),
    ("Official documentation", "Docker documentation", "https://github.com/docker/docs/archive/HEAD.zip",
     "docker-docs.zip", "Apache 2.0"),
    ("Official documentation", "Ansible documentation", "https://github.com/ansible/ansible-documentation/archive/HEAD.zip",
     "ansible-documentation.zip", "GPL-3.0"),
    ("Official documentation", "Prometheus documentation", "https://github.com/prometheus/docs/archive/HEAD.zip",
     "prometheus-docs.zip", "Apache 2.0"),
    ("Official documentation", "Windows Server documentation",
     "https://github.com/MicrosoftDocs/windowsserverdocs/archive/HEAD.zip", "windowsserverdocs.zip", "CC BY 4.0"),
    ("Official documentation", "PowerShell documentation", "https://github.com/MicrosoftDocs/PowerShell-Docs/archive/HEAD.zip",
     "PowerShell-Docs.zip", "CC BY 4.0"),
    ("Official documentation", "PostgreSQL manual", "https://www.postgresql.org/files/documentation/pdf/17/postgresql-17-A4.pdf",
     "PostgreSQL 17 manual (A4).pdf", "PostgreSQL Licence"),
    ("Official documentation", "Pro Git book", "https://github.com/progit/progit2/archive/HEAD.zip", "progit2.zip",
     "CC BY-NC-SA 3.0"),
    ("Official documentation", "tldr command-line pages", "https://github.com/tldr-pages/tldr/archive/HEAD.zip",
     "tldr-pages.zip", "CC BY 4.0"),
    ("Official documentation", "Linux kernel admin guide (kernel docs)",
     "https://github.com/torvalds/linux/archive/refs/tags/v6.6.tar.gz", "linux-6.6-source-with-docs.tar.gz", "GPL-2.0"),
    ("Tool catalogues", "Awesome Sysadmin", "https://github.com/awesome-foss/awesome-sysadmin/archive/HEAD.zip",
     "awesome-sysadmin.zip", "CC BY-SA 4.0"),
    ("Tool catalogues", "Awesome Selfhosted", "https://github.com/awesome-selfhosted/awesome-selfhosted/archive/HEAD.zip",
     "awesome-selfhosted.zip", "CC BY-SA 3.0"),
    ("Tool catalogues", "Awesome DevOps", "https://github.com/wmariuss/awesome-devops/archive/HEAD.zip",
     "awesome-devops.zip", "CC0"),
    ("Tool catalogues", "Awesome Security", "https://github.com/sbilly/awesome-security/archive/HEAD.zip",
     "awesome-security.zip", "MIT"),
    ("Tool catalogues", "Awesome Incident Response", "https://github.com/meirwah/awesome-incident-response/archive/HEAD.zip",
     "awesome-incident-response.zip", "Apache 2.0"),
    ("Tool catalogues", "Awesome Monitoring", "https://github.com/crazy-canux/awesome-monitoring/archive/HEAD.zip",
     "awesome-monitoring.zip", "see repository"),
    ("Tool catalogues", "Free for Dev", "https://github.com/ripienaar/free-for-dev/archive/HEAD.zip",
     "free-for-dev.zip", "MIT"),
    ("Tool catalogues", "Public APIs", "https://github.com/public-apis/public-apis/archive/HEAD.zip",
     "public-apis.zip", "MIT"),
]


def lifecycles(sink, st):
    """Release and end-of-life dates for ~400 products (OSes, databases, runtimes, devices, cloud services)."""
    stamp = st.get("eol")
    if stamp and stamp > (dt.date.today() - dt.timedelta(days=30)).isoformat():
        return 0
    s = session()
    r = get(s, "https://endoflife.date/api/all.json")
    if not r:
        return 0
    rows = []
    for p in r.json():
        time.sleep(0.3)
        pr = get(s, f"https://endoflife.date/api/{p}.json", tries=3)
        if not pr:
            continue
        for c in pr.json():
            rows.append([p, str(c.get("cycle", "")), c.get("codename"), c.get("releaseDate"), str(c.get("lts", "")),
                         str(c.get("support", "")), str(c.get("eol", "")), str(c.get("extendedSupport", "")),
                         c.get("latest"), c.get("latestReleaseDate"), c.get("link")])
    today = dt.date.today().isoformat()
    wb = new_book()
    add_sheet(wb, "All release cycles", ["Product", "Cycle", "Codename", "Released", "LTS", "Active support until",
                                         "End of life", "Extended support", "Latest version", "Latest release",
                                         "Release notes"], rows, {"Product": 26, "Release notes": 50})
    eol_soon = [x for x in rows if x[6][:4].isdigit() and today <= x[6] <= str(dt.date.today().year + 1) + today[4:]]
    add_sheet(wb, "EOL in next 12 months", ["Product", "Cycle", "Codename", "Released", "LTS", "Active support until",
                                            "End of life", "Extended support", "Latest version", "Latest release",
                                            "Release notes"], eol_soon, {"Product": 26})
    base = f"{TECH}/Technology Lifecycles"
    save_book(sink, f"{base}/Product release and end-of-life dates {today}.xlsx", wb)
    meta_note(sink, base, {"source": "endoflife.date", "url": "https://endoflife.date", "license": "MIT"})
    st["eol"] = today
    return len(rows)


def stackexchange(sink, st):
    """Stack Exchange data dumps for IT, sysadmin, security and developer sites (archive.org, CC BY-SA)."""
    done = set(st.setdefault("se_done", []))
    s = session()
    n = 0
    for site in SE_SITES:
        if site in done or sink.full():
            continue
        name = f"{site}.7z"
        if _download(s, f"https://archive.org/download/stackexchange/{name}", 3 * 2 ** 30, sink,
                     f"{TECH}/Q&A Archives (Stack Exchange)/{name}"):
            n += 1
        st["se_done"].append(site)
    if n:
        meta_note(sink, f"{TECH}/Q&A Archives (Stack Exchange)", {
            "source": "Stack Exchange data dump (Internet Archive)", "url": "https://archive.org/details/stackexchange",
            "license": "CC BY-SA (Stack Exchange contributors)",
            "format": "7z of XML: Posts, Comments, Users, Tags, Votes, Badges, PostHistory, PostLinks"})
    return n


def docs(sink, st):
    s = session()
    n = 0
    for folder, title, url, name, lic in DOCS:
        if sink.full():
            break
        key = f"doc_{name}"
        stamp = st.get(key)
        if stamp and stamp > (dt.date.today() - dt.timedelta(days=90)).isoformat():
            continue
        dest = f"{TECH}/{folder}/{title}"
        if _download(s, url, 3 * 2 ** 30, sink, f"{dest}/{dt.date.today()} {name}"):
            meta_note(sink, dest, {"source": title, "url": url, "license": lic})
            n += 1
        st[key] = dt.date.today().isoformat()
    return n


# Whole Zenodo records kept together: (record id, destination folder)
RECORDS = [(8196385, f"{CLOUD}/Loghub System Logs")]


def records(sink, st):
    """Large curated corpora downloaded file by file (Loghub: 16 system logs, CC BY 4.0)."""
    s = session()
    done = st.setdefault("records_done", [])
    n = 0
    for rid, dest in RECORDS:
        r = get(s, f"https://zenodo.org/api/records/{rid}")
        if not r:
            continue
        d = r.json()
        for f in d.get("files", []):
            key = f"{rid}/{f['key']}"
            if key in done or sink.full():
                continue
            if _download(s, f["links"]["self"], 3 * 2 ** 30, sink, f"{dest}/{f['key']}"):
                n += 1
            done.append(key)
        if not st.get(f"records_meta_{rid}"):
            meta_note(sink, dest, {"source": d["metadata"]["title"], "record": d["links"]["self_html"],
                                   "doi": d.get("doi"), "license": (d["metadata"].get("license") or {}).get("id"),
                                   "also": "https://github.com/logpai/loghub (2k-line labelled samples + templates)"})
            st[f"records_meta_{rid}"] = True
    if "loghub_repo" not in done and not sink.full():
        if _download(s, "https://github.com/logpai/loghub/archive/HEAD.zip", 2 ** 30, sink,
                     f"{CLOUD}/Loghub System Logs/loghub repository (samples and templates).zip"):
            n += 1
        done.append("loghub_repo")
    return n


SOURCES = {"records": records, "eol": lifecycles, "stackexchange": stackexchange, "techdocs": docs}
