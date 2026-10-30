# ops-data-collector

GitHub Actions collector of operational research data for a **security & IT managed-services** business
(24/7 video monitoring, SOC, field maintenance, IT help desk, cloud) serving mostly US hotels, cruise lines,
marinas and residential/retail clients. Files go straight from the runner to Google Drive with rclone.

## What it collects

**Public Data** (openly licensed; each folder's source and licence are recorded in `_state`), sorted by topic and subtopic

| Folder | Sources |
|---|---|
| 1 Threat Intelligence | CISA KEV, CSE-CIC-IDS2018 network flows (6.4 GB), NVD CVE records per month, MITRE ATT&CK, Zenodo and government open-data portal (Socrata) datasets |
| 2 Standards & Compliance | NIST SP 800-53 Rev 5 (XLSX + DOCX per family), datasets |
| 3 IT Service Management | UCI ITSM incident event log, datasets |
| 4 Physical Security & Surveillance | Zenodo + open-data portal datasets |
| 5 Hospitality & Maritime Operations | Hotel booking demand, datasets |
| 6 Cloud & Infrastructure Operations | Loghub system logs (16 systems, 5.6 GB), Zenodo + open-data portal datasets |
| 7 Workforce & Business Benchmarks | Zenodo + open-data portal datasets |
| 9 IT & Developer Tools | product release/end-of-life dates (endoflife.date), Stack Exchange archives (Server Fault, Super User, Security, Ask Ubuntu, Unix, DBA, DevOps…), Kubernetes/Docker/Ansible/Prometheus/Windows Server/PowerShell/PostgreSQL docs, Pro Git, tldr, curated tool catalogues, IT documentation & runbooks (GitHub topic it-documentation, Microsoft Engineering Playbook, Gruntwork Runbooks, onboarding templates), companies by technology stack (Leadita), Kaggle datasets |
| 10 Videos & Talks | openly licensed talks, webinars, conference recordings and documentaries (Internet Archive), MP4 + subtitles, by topic (SOC, incident response, surveillance, IT operations, DevOps/SRE, business of IT services, hospitality & maritime) |
| 8 Books & Knowledge Library | NIST security publications, open-access books (OpenAlex, CC/public domain), Wikipedia topic articles as DOCX, OWASP, CWE, CAPEC, D3FEND, Sigma, Atomic Red Team |

**Fictional Company - Harborlight Secure Systems** (synthetic, made-up names, `.example` domains):
CRM and pipeline, contracts (DOCX), SOC alert logs, incident registers and reports, work orders, help desk
tickets, asset register, double-entry books (GL, trial balance, PDF invoices, AR aging, bank statements, budgets,
financial statements), payroll, timesheets, shift rosters, client service reports, board packs, meeting minutes,
e-mail exports (.eml), and bulk telemetry (access-control events, recorder health metrics, device syslog).
History runs from 2016-01 and is extended month by month; reruns reproduce past months exactly.

## Running

- Secret `RCLONE_CONF`: an rclone.conf with a Google Drive remote named `[pax]`.
- Optional secret `KAGGLE_API_TOKEN` (kaggle.com → Settings → API → Create New Token) for Kaggle datasets in every topic folder.
- Variable `LIVE=true` turns on uploads; without it every run is a dry run.
- Schedule: every 6 hours; manual runs via *Actions → collect → Run workflow*.
- State lives on Drive in `_state/`, so runs resume where the last one stopped.
