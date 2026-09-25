<div align="center">

<img src="assets/gandiv-banner.svg" alt="GANDIV — Target Intelligence / OSINT Reconnaissance" width="100%">

<br>

<strong>Never Miss Target Intelligence.</strong>

<br>

Multi-source OSINT reconnaissance engine — menu-driven, AI-powered, built in public.

<br><br>

<img src="https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white">
<img src="https://img.shields.io/badge/OSINT-Reconnaissance-DC2626?style=flat-square">
<img src="https://img.shields.io/badge/AI-Gemini%203.8-4285F4?style=flat-square&logo=google&logoColor=white">
<img src="https://img.shields.io/badge/License-MIT-F59E0B?style=flat-square">
<img src="https://img.shields.io/badge/Status-Active-059669?style=flat-square">

</div>

---

# Overview

**GANDIV** is an open-source OSINT reconnaissance engine designed to automate the information-gathering phase of a security assessment.

Named after **Arjun's bow** from the Mahabharata, GANDIV is built around a simple idea:

> **Collect signals. Correlate evidence. Reduce noise. Produce intelligence.**

A target can be a **domain, email, phone number, username, IP, URL, or name**.

GANDIV routes the target through the appropriate reconnaissance modules, normalizes and deduplicates the results, scores confidence, optionally sends the findings to Gemini for analysis, and generates structured reports.

## Core Capabilities

- Multi-module OSINT reconnaissance
- Multi-source intelligence collection
- Deduplication and confidence scoring
- Optional Gemini-powered analysis
- JSON, HTML, and Markdown reporting
- Interactive menu and CLI workflows
- Concurrent scanning with resumable checkpoints

Built for **bug bounty hunters, penetration testers, threat intelligence analysts, and red teamers**.

---

# Workflow

```mermaid
flowchart TD

    A["Target Input<br/>Domain / Email / Phone / Username / IP / URL / Name"]
    B["Target Detection<br/>Type + Validation"]
    C["Orchestrator<br/>Module Selection"]

    A --> B
    B --> C

    C --> D1["Domain Recon"]
    C --> D2["People OSINT"]
    C --> D3["Web Recon"]
    C --> D4["Infrastructure Recon"]
    C --> D5["OSINT Aggregator"]

    D1 --> E["Raw Findings"]
    D2 --> E
    D3 --> E
    D4 --> E
    D5 --> E

    E --> F["Normalizer"]
    F --> G["Deduplication"]
    G --> H["Confidence Scoring"]

    H --> I{"AI Analysis Enabled?"}

    I -- "No" --> K["Report Generator"]
    I -- "Yes" --> J["Gemini Analysis"]

    J --> K

    K --> L1["JSON"]
    K --> L2["HTML"]
    K --> L3["Markdown"]

    L1 --> M["gandiv_reports/"]
    L2 --> M
    L3 --> M
Scan Pipeline
                         ┌─────────────────────┐
                         │       INPUT         │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   DETECT TARGET     │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   SELECT MODULES    │
                         └──────────┬──────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
          ┌────────┐            ┌────────┐            ┌────────┐
          │ Domain │            │ People │            │  Web   │
          └────┬───┘            └────┬───┘            └────┬───┘
               │                     │                     │
               └─────────────────────┼─────────────────────┘
                                     │
                                     ▼
                         ┌─────────────────────┐
                         │ COLLECT FINDINGS    │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ NORMALIZE + DEDUP   │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │ CONFIDENCE SCORE    │
                         └──────────┬──────────┘
                                    │
                         ┌──────────┴──────────┐
                         │                     │
                         ▼                     ▼
                  ┌──────────────┐      ┌──────────────┐
                  │    REPORT    │      │    GEMINI    │
                  └──────┬───────┘      └──────┬───────┘
                         │                     │
                         └──────────┬──────────┘
                                    │
                                    ▼
                         ┌─────────────────────┐
                         │   JSON / HTML / MD   │
                         └─────────────────────┘
Quick Start
# Clone
git clone https://github.com/CalculusGuy/GANDIV.git
cd GANDIV

# Install
pip install -r requirements.txt

# Configure optional API keys
cp .env.example .env

# Launch interactive interface
python main.py
Full CLI Scan
python main.py scan \
    --target example.com \
    --full \
    --report json,html,markdown
Interactive Mode
[1]  People OSINT          → Email, phone, username, name
[2]  Domain Recon          → Subdomains, DNS, WHOIS, certs
[3]  Web Recon             → Tech stack, WAF, headers, JS secrets
[4]  Infrastructure Recon  → IPs, ASN, Shodan, Censys, SSL
[5]  Breach & Leak Check   → HIBP, paste sites
[6]  Username Enumeration  → Multi-platform
[7]  Reverse Image Search  → Google, Yandex, TinEye
[8]  Full OSINT            → All modules against a target
[9]  Custom Scan           → Select modules manually
Modules
Module	What It Does	Status
domain_recon	Subdomains, DNS, WHOIS, zone transfer, Wayback URLs	Stable
web_recon	Tech fingerprinting, WAF detection, security headers, JS secrets, exposed paths	Stable
infra_recon	IP resolution, ASN, Shodan/Censys, SSL analysis, cloud bucket enumeration	Stable
email_recon	Email/username dispatch, HIBP, pattern generation, Gravatar	Stable
email_osint	Gravatar, HIBP, registration signals, search dorks	Working
phone_osint	Country/carrier inference, WhatsApp presence, dorks, paste search	Working
person_recon	Person/org search via search engines and GitHub API	Stable
osint_aggregator	Google/GitHub dorks, paste search, cross-reference	Stable
breach_osint	Breach correlation via HIBP / XposedOrNot	Stub
username_osint	Multi-platform username enumeration	Stub
name_osint	Person search via search engines and social sources	Stub
image_osint	Reverse image search and EXIF extraction	Stub
AI Analysis

GANDIV can optionally send normalized findings to Gemini 3.8 Flash for structured analysis.

The analysis layer is designed to produce:

Executive summary
Key findings
Risk assessment
Attack-surface interpretation
Cross-finding correlations
Actionable recommendations
Gemini Fallback Chain
3.8-flash
    │
    ├── rate limit / failure
    ▼
2.5-flash
    │
    ├── rate limit / failure
    ▼
2.5-pro
    │
    ├── rate limit / failure
    ▼
2.0-flash

Configure the API key in .env:

GEMINI_API_KEY=your_key_here
Reporting

Every scan can produce three report formats:

Format	Intended Use
JSON	Automation, CI/CD, dashboards, downstream tooling
HTML	Human review, sharing, presentations
Markdown	GitHub, documentation, writeups

Reports are stored in:

gandiv_reports/
CLI Reference
# Interactive menu
python main.py

# Domain scan
python main.py scan \
    --target example.com \
    --type domain \
    --full

# Email OSINT
python main.py scan \
    --target user@example.com \
    --type people-email \
    --report json,markdown

# Phone OSINT
python main.py scan \
    --target +919999999999 \
    --type people-phone

# Username enumeration
python main.py scan \
    --target johndoe \
    --type people-username

# Resume interrupted scan
python main.py resume \
    --checkpoint path/to/checkpoint.json

# Verify environment
python main.py check

# Configure API keys
python main.py config-wizard
Options
Flag	Description	Default
--target, -t	Domain, email, phone, username, IP, or URL	Required
--type	Force target type	Auto-detect
--full	Run the full module set	Off
--threads	Concurrent workers	10
--report	json, html, markdown, or comma-separated	json,html
--output-dir	Override report directory	gandiv_reports
--insecure	Disable TLS verification	Off
--quiet, -q	Suppress banner	Off
Architecture
                           ┌──────────────────────┐
                           │     Target Input     │
                           │ Domain / Email / ... │
                           └──────────┬───────────┘
                                      │
                                      ▼
                           ┌──────────────────────┐
                           │  Target Detection &  │
                           │      Validation      │
                           └──────────┬───────────┘
                                      │
                                      ▼
                           ┌──────────────────────┐
                           │     Orchestrator     │
                           └──────────┬───────────┘
                                      │
              ┌───────────────────────┼───────────────────────┐
              │                       │                       │
              ▼                       ▼                       ▼
       ┌──────────────┐       ┌──────────────┐       ┌──────────────┐
       │ Domain Recon │       │ People OSINT │       │  Web / Infra │
       └──────┬───────┘       └──────┬───────┘       └──────┬───────┘
              │                       │                       │
              └───────────────────────┼───────────────────────┘
                                      │
                                      ▼
                           ┌──────────────────────┐
                           │     Normalizer       │
                           │  Dedup + Confidence  │
                           └──────────┬───────────┘
                                      │
                                      ▼
                           ┌──────────────────────┐
                           │  Gemini AI Analysis  │
                           │       Optional       │
                           └──────────┬───────────┘
                                      │
                                      ▼
                           ┌──────────────────────┐
                           │   Report Generator   │
                           │   JSON / HTML / MD   │
                           └──────────────────────┘
Project Structure
GANDIV/
│
├── main.py
├── requirements.txt
├── README.md
├── EXAMPLES.md
├── LICENSE
├── .env.example
├── .gitignore
│
├── gandiv/
│   │
│   ├── config.py
│   ├── models.py
│   ├── logger.py
│   ├── menu.py
│   ├── orchestrator.py
│   ├── normalizer.py
│   ├── llm_analyzer.py
│   │
│   ├── modules/
│   │   ├── domain_recon.py
│   │   ├── web_recon.py
│   │   ├── infra_recon.py
│   │   ├── email_recon.py
│   │   ├── email_osint.py
│   │   ├── phone_osint.py
│   │   ├── person_recon.py
│   │   ├── osint_aggregator.py
│   │   ├── breach_osint.py
│   │   ├── username_osint.py
│   │   ├── name_osint.py
│   │   └── image_osint.py
│   │
│   ├── reporters/
│   │   ├── json_reporter.py
│   │   ├── html_reporter.py
│   │   └── markdown_reporter.py
│   │
│   └── utils/
│       ├── http_client.py
│       └── validators.py
│
└── tests/
    └── test_modules.py
API Integrations

API keys are optional. Adding them increases coverage.

Service	Purpose	Availability
Gemini	AI analysis of findings	Free tier
HIBP	Breach exposure checks	Paid
Shodan	Open-port intelligence	Paid
Censys	Infrastructure intelligence	Free tier available
GitHub	Code/search intelligence	Free PAT
VirusTotal	Domain/IP reputation	Free tier
Numverify	Phone validation	Free tier

Configure keys through .env:

python main.py config-wizard
Responsible Use

GANDIV is intended for authorized security research and defensive intelligence work.

Only use it against systems and targets you own or have explicit authorization to assess.

Do not use GANDIV to:

Scan systems without authorization
Conduct surveillance on individuals
Circumvent security controls
Violate privacy or data-protection laws

GANDIV collects information from publicly accessible sources. It does not bypass authentication, compromise accounts, or access private systems.

Roadmap
Phase 1 — Foundation
 Domain, web, and infrastructure modules
 Concurrent scanning
 JSON / HTML / Markdown reporting
 Interactive menu
Phase 2 — People OSINT
 Email OSINT
 Phone OSINT
 Username enumeration
 Name OSINT
 Breach correlation
 Reverse image search + EXIF
Phase 3 — AI & Intelligence
 Gemini LLM analysis
 Cross-target correlation
 Threat actor attribution
 Historical tracking
 Confidence-scoring refinement
Phase 4 — DevSecOps
 Docker image
 GitHub Actions CI/CD
 SARIF output
 Scheduled scans
 REST API
Technology Stack
Layer	Technology
Language	Python 3.11+
Async	asyncio + aiohttp
Concurrency	ThreadPoolExecutor
CLI	Typer + Rich
HTTP	requests + aiohttp
DNS	dnspython
WHOIS	python-whois
AI	Gemini 3.8 Flash
Reporting	Jinja2, JSON, Markdown
Testing	pytest
Contributing

Contributions are welcome.

Useful areas include:

New OSINT modules
Additional intelligence sources
Correlation and normalization improvements
Bug fixes
Test coverage
Documentation

Open an issue before large architectural changes.

License

MIT License. See LICENSE.

Author

Nilanjan Chowdhury

Cybersecurity Researcher | Ethical Hacker | Builder of SUDARSHAN & BRAMHASTRA

GitHub: @CalculusGuy
Medium: @nilanjan.calculus
Portfolio: calculusguy.github.io
<div align="center">

GANDIV

Reconnaissance, not surveillance.

<sub>Never Miss Target Intelligence.</sub>

</div> ```
