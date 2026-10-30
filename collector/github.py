"""GitHub: technical repositories, Jupyter notebooks and open-source apps for a security & IT services business.

Only licensed repositories are taken. Everything is filed by topic, never by where it came from."""
import os
import re
import time

from .common import get, safe, session
from .public import PUB, _download

REPOS = f"{PUB}/11 GitHub Repositories"
NOTEBOOKS = f"{PUB}/12 Jupyter Notebooks"
APPS = f"{PUB}/13 Software & Apps"

REPO_TOPICS = {  # folder: GitHub topics
    "SOC, SIEM & Detection": ["siem", "soc", "detection-engineering", "threat-hunting", "blue-team", "sigma-rules",
                              "security-monitoring", "log-analysis"],
    "Incident Response & Forensics": ["incident-response", "dfir", "digital-forensics", "malware-analysis",
                                      "memory-forensics"],
    "Threat Intelligence & OSINT": ["threat-intelligence", "osint", "cti", "ioc"],
    "Vulnerability Management & Pentesting": ["vulnerability-scanner", "penetration-testing", "pentesting",
                                              "vulnerability-management", "red-team"],
    "Video Surveillance & CCTV": ["cctv", "nvr", "video-surveillance", "ip-camera", "rtsp", "onvif", "surveillance"],
    "Access Control & Physical Security": ["access-control", "rfid", "physical-security", "door-access"],
    "IT Service Management & Helpdesk": ["itsm", "helpdesk", "service-desk", "ticketing-system", "help-desk"],
    "Asset & Configuration Management": ["asset-management", "it-asset-management", "cmdb", "inventory-management"],
    "Monitoring & Observability": ["monitoring", "observability", "network-monitoring", "snmp", "uptime-monitor",
                                   "alerting"],
    "Networking & Remote Access": ["network-automation", "vpn", "wireguard", "remote-desktop", "rmm"],
    "DevOps, Cloud & Infrastructure": ["devops", "infrastructure-as-code", "ansible", "kubernetes", "terraform",
                                       "homelab", "self-hosted", "backup"],
    "IoT & Building Automation": ["iot", "building-automation", "home-automation", "bms", "smart-building"],
    "Hospitality & Maritime Tech": ["hotel-management", "hotel-booking", "property-management", "pms", "maritime",
                                    "ais"],
    "Sysadmin & Scripting": ["sysadmin", "powershell", "bash-scripts", "windows-administration", "linux-administration"],
}

NOTEBOOK_TOPICS = {
    "Intrusion & Anomaly Detection": ["intrusion detection", "network anomaly detection", "cicids", "nsl-kdd"],
    "Malware & Phishing Analysis": ["malware detection", "phishing detection", "spam detection"],
    "Log Analysis & AIOps": ["log anomaly detection", "log analysis", "aiops", "incident prediction"],
    "Threat Hunting & SOC Analytics": ["threat hunting", "siem analytics", "security analytics", "cyber security"],
    "Video Analytics & CCTV": ["cctv object detection", "surveillance video", "person detection", "anomaly detection video"],
    "IT Operations & Predictive Maintenance": ["predictive maintenance", "server failure prediction", "it tickets",
                                               "ticket classification"],
    "Cloud & Infrastructure Analytics": ["cloud cost", "kubernetes monitoring", "capacity planning"],
    "Hospitality & Maritime Analytics": ["hotel booking", "hotel cancellation", "ship ais", "cruise"],
    "Fraud & Risk Analytics": ["fraud detection", "credit card fraud", "risk scoring"],
}

APPS_LIST = {  # folder: GitHub repositories of open-source apps
    "SOC & SIEM": ["wazuh/wazuh", "Security-Onion-Solutions/securityonion", "TheHive-Project/TheHive",
                   "MISP/MISP", "OpenCTI-Platform/opencti", "Graylog2/graylog2-server", "crowdsecurity/crowdsec"],
    "Endpoint & Network Security": ["osquery/osquery", "Velocidex/velociraptor", "OISF/suricata", "zeek/zeek",
                                    "fleetdm/fleet", "ossec/ossec-hids"],
    "Vulnerability Scanning": ["projectdiscovery/nuclei", "zaproxy/zaproxy", "greenbone/openvas-scanner",
                               "sqlmapproject/sqlmap", "nmap/nmap", "aquasecurity/trivy"],
    "Video Surveillance (NVR)": ["blakeblackshear/frigate", "ZoneMinder/zoneminder", "Motion-Project/motion",
                                 "bluenviron/mediamtx", "AlexxIT/go2rtc", "kerberos-io/agent"],
    "Helpdesk & ITSM": ["glpi-project/glpi", "osTicket/osTicket", "zammad/zammad", "freescout-helpdesk/freescout",
                        "Combodo/iTop"],
    "Asset & Network Inventory": ["snipe/snipe-it", "netbox-community/netbox", "allegro/ralph"],
    "Monitoring": ["zabbix/zabbix", "prometheus/prometheus", "grafana/grafana", "netdata/netdata",
                   "louislam/uptime-kuma", "librenms/librenms", "icinga/icinga2", "influxdata/telegraf"],
    "Remote Support & Management": ["rustdesk/rustdesk", "Ylianst/MeshCentral", "amidaware/tacticalrmm",
                                    "apache/guacamole-client"],
    "Networking & VPN": ["netbirdio/netbird", "OpenVPN/openvpn", "pi-hole/pi-hole", "wg-easy/wg-easy"],
    "Passwords & Secrets": ["keepassxreboot/keepassxc", "dani-garcia/vaultwarden"],
    "Backup & Storage": ["restic/restic", "borgbackup/borg", "duplicati/duplicati", "rclone/rclone"],
    "Containers & Infrastructure": ["k3s-io/k3s", "portainer/portainer", "opentofu/opentofu", "docker/compose",
                                    "PowerShell/PowerShell"],
    "Automation & IoT": ["node-red/node-red", "home-assistant/core", "openhab/openhab-distro"],
    "Hospitality": ["Qloapps/QloApps"],
}
ASSET_OK = re.compile(r"(windows|win64|win-x64|x64\.(msi|exe)|amd64|x86_64|linux64|\.msi$|setup.*\.exe$|\.deb$|"
                      r"\.rpm$|\.appimage$)", re.I)
ASSET_BAD = re.compile(r"(arm|aarch64|i386|i686|386|mips|ppc|s390|riscv|darwin|macos|\.sig$|\.asc$|\.sha\d*|"
                       r"checksums|sbom|\.pem$|\.minisig$|debug|symbols)", re.I)


def _gh():
    s = session()
    if os.environ.get("GITHUB_TOKEN"):
        s.headers["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    s.headers["Accept"] = "application/vnd.github+json"
    return s


def _search(s, q, page):
    time.sleep(2.2)  # search API: 30 requests a minute
    r = get(s, "https://api.github.com/search/repositories",
            params={"q": q, "sort": "stars", "order": "desc", "per_page": 30, "page": page})
    return r.json().get("items", []) if r else []


def _licensed(repo):
    lic = (repo.get("license") or {}).get("spdx_id")
    return lic and lic != "NOASSERTION"


def repos(sink, st, per_topic=3, max_kb=400 * 1024):
    """Default-branch archives of the most-starred licensed repositories per topic."""
    s = _gh()
    done = st.setdefault("gh_repos", {})
    pages = st.setdefault("gh_repo_page", {})
    n = 0
    for folder, topics in REPO_TOPICS.items():
        for t in topics:
            if sink.full():
                return n
            page = pages.get(t, 1)
            items = _search(s, f"topic:{t} archived:false", page)
            pages[t] = page + 1 if items else 1
            took = 0
            for repo in items:
                if took >= per_topic or sink.full():
                    break
                name = repo["full_name"]
                if name in done or not _licensed(repo) or repo.get("size", 0) > max_kb or repo.get("fork"):
                    continue
                dest = f"{REPOS}/{folder}/{safe(name.replace('/', ' - '), 100)}.zip"
                if _download(s, f"https://api.github.com/repos/{name}/zipball", 2 * 2 ** 30, sink, dest):
                    sink.state.data.setdefault("catalog", {})[dest] = {
                        "source": repo["html_url"], "license": repo["license"]["spdx_id"],
                        "stars": repo.get("stargazers_count"), "description": (repo.get("description") or "")[:500]}
                    took += 1
                    n += 1
                done[name] = repo.get("pushed_at")
    return n


def notebooks(sink, st, per_query=3, per_repo=60, max_mb=25):
    """Jupyter notebooks (.ipynb) from licensed notebook repositories, with their folder structure."""
    s = _gh()
    done = st.setdefault("nb_repos", [])
    done_set = set(done)
    pages = st.setdefault("nb_page", {})
    n = 0
    for folder, queries in NOTEBOOK_TOPICS.items():
        for q in queries:
            if sink.full():
                return n
            page = pages.get(q, 1)
            items = _search(s, f'{q} language:jupyter-notebook archived:false', page)
            pages[q] = page + 1 if items else 1
            took = 0
            for repo in items:
                if took >= per_query or sink.full():
                    break
                name = repo["full_name"]
                about = " ".join([name, repo.get("description") or "", " ".join(repo.get("topics") or [])]).lower()
                if name in done_set or not _licensed(repo) or not all(w in about for w in q.lower().split()):
                    continue
                done.append(name)
                done_set.add(name)
                tree = get(s, f"https://api.github.com/repos/{name}/git/trees/{repo['default_branch']}",
                           params={"recursive": "1"})
                files = [f for f in (tree.json().get("tree", []) if tree else [])
                         if f.get("type") == "blob" and f["path"].lower().endswith(".ipynb")
                         and f.get("size", 0) <= max_mb * 2 ** 20]
                got = 0
                for f in files[:per_repo]:
                    url = f"https://raw.githubusercontent.com/{name}/{repo['default_branch']}/{f['path']}"
                    if _download(s, url, max_mb * 2 ** 20, sink,
                                 f"{NOTEBOOKS}/{folder}/{safe(name.replace('/', ' - '), 90)}/{f['path']}"):
                        got += 1
                if got:
                    sink.state.data.setdefault("catalog", {})[f"{NOTEBOOKS}/{folder}/{name}"] = {
                        "source": repo["html_url"], "license": repo["license"]["spdx_id"], "notebooks": got}
                    took += 1
                    n += got
    return n


def apps(sink, st, app_cap=2 * 2 ** 30):
    """Latest release of each app: Windows / Linux x64 installers and packages, else the release source archive.
    A new release replaces nothing; it is added under its own version folder."""
    s = _gh()
    done = st.setdefault("app_release", {})
    n = 0
    for folder, names in APPS_LIST.items():
        for name in names:
            if sink.full():
                return n
            r = get(s, f"https://api.github.com/repos/{name}/releases/latest")
            rel = r.json() if r else None
            if not rel or not rel.get("tag_name"):
                tags = get(s, f"https://api.github.com/repos/{name}/tags", params={"per_page": 1})
                tag = (tags.json() or [{}])[0].get("name") if tags else None
                if not tag:
                    continue
                rel = {"tag_name": tag, "assets": [], "zipball_url": f"https://api.github.com/repos/{name}/zipball/{tag}"}
            tag = rel["tag_name"]
            if done.get(name) == tag:
                continue
            app = name.split("/")[1]
            dest = f"{APPS}/{folder}/{safe(app, 60)}/{safe(tag, 40)}"
            assets = [a for a in rel.get("assets", []) if ASSET_OK.search(a["name"]) and not ASSET_BAD.search(a["name"])]
            total, got = 0, 0
            for a in sorted(assets, key=lambda a: a["size"]):
                total += a["size"]
                if total > app_cap or sink.full():
                    break
                if _download(s, a["browser_download_url"], app_cap, sink, f"{dest}/{a['name']}"):
                    got += 1
            if _download(s, rel.get("zipball_url") or f"https://api.github.com/repos/{name}/zipball/{tag}", app_cap,
                         sink, f"{dest}/{safe(app, 60)}-{safe(tag, 40)}-source.zip"):
                got += 1
            if got:
                done[name] = tag
                sink.state.data.setdefault("catalog", {})[dest] = {"source": f"https://github.com/{name}",
                                                                   "release": tag, "files": got}
                n += 1
    return n


SOURCES = {"ghrepos": repos, "notebooks": notebooks, "apps": apps}
