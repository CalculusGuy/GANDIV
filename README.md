# GANDIV

```text
 ██████╗  █████╗ ███╗   ██╗██████╗ ██╗██╗   ██╗
██╔════╝ ██╔══██╗████╗  ██║██╔══██╗██║██║   ██║
██║  ███╗███████║██╔██╗ ██║██║  ██║██║██║   ██║
██║   ██║██╔══██║██║╚██╗██║██║  ██║██║╚██╗ ██╔╝
╚██████╔╝██║  ██║██║ ╚████║██████╔╝██║ ╚████╔╝
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═══╝

Multi-source OSINT Reconnaissance Engine

Collect signals. Correlate evidence. Reduce noise. Produce intelligence.

GANDIV automates OSINT reconnaissance against domains, emails, phone numbers,
usernames, IPs, URLs and names using multiple reconnaissance modules.

Workflow
                         ┌──────────────────┐
                         │   TARGET INPUT   │
                         │ Domain / Email   │
                         │ Phone / IP / URL │
                         │ Username / Name  │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │ TARGET DETECTION │
                         │  Type + Validate │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │   ORCHESTRATOR   │
                         └────────┬─────────┘
                                  │
             ┌────────────────────┼────────────────────┐
             ▼                    ▼                    ▼
      ┌─────────────┐      ┌─────────────┐      ┌─────────────┐
      │ Domain Recon│      │ People OSINT│      │ Web / Infra │
      └──────┬──────┘      └──────┬──────┘      └──────┬──────┘
             │                    │                    │
             └────────────────────┼────────────────────┘
                                  ▼
                         ┌──────────────────┐
                         │ COLLECT FINDINGS │
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │ NORMALIZE + DEDUP│
                         └────────┬─────────┘
                                  │
                                  ▼
                         ┌──────────────────┐
                         │ CONFIDENCE SCORE │
                         └────────┬─────────┘
                                  │
                         ┌────────┴────────┐
                         ▼                 ▼
                  ┌─────────────┐   ┌─────────────┐
                  │    REPORT   │   │    GEMINI   │
                  └──────┬──────┘   │   Optional  │
                         │           └──────┬──────┘
                         └──────────┬───────┘
                                    ▼
                         ┌──────────────────┐
                         │ JSON / HTML / MD │
                         └──────────────────┘
Features
Domain reconnaissance
Web reconnaissance
Infrastructure intelligence
Email and phone OSINT
Username and person enumeration
Search-engine/GitHub OSINT
Finding normalization and deduplication
Confidence scoring
Optional Gemini AI analysis
JSON, HTML and Markdown reports
Interactive menu
CLI support
Concurrent scanning
Resumable scans
Installation
git clone https://github.com/CalculusGuy/GANDIV.git
cd GANDIV

pip install -r requirements.txt

cp .env.example .env

Optional API keys can be configured in .env.

GEMINI_API_KEY=your_key_here
User Guide
1. Start GANDIV
python main.py

You will get the interactive menu:

[1] People OSINT
[2] Domain Recon
[3] Web Recon
[4] Infrastructure Recon
[5] Breach & Leak Check
[6] Username Enumeration
[7] Reverse Image Search
[8] Full OSINT
[9] Custom Scan

Select the required module and provide the target.

2. Domain Recon
python main.py scan \
    --target example.com \
    --type domain \
    --full

Can collect:

Subdomains
DNS
WHOIS
Certificates
Wayback URLs
3. Email OSINT
python main.py scan \
    --target user@example.com \
    --type people-email

Possible sources include:

HIBP
Gravatar
Registration signals
Search engines
Username patterns
4. Phone OSINT
python main.py scan \
    --target +919999999999 \
    --type people-phone
5. Username OSINT
python main.py scan \
    --target johndoe \
    --type people-username
6. Full OSINT Scan
python main.py scan \
    --target example.com \
    --full \
    --report json,html,markdown

This runs the available reconnaissance modules and generates reports.

Reports

Reports are stored in:

gandiv_reports/

Supported formats:

JSON      → Automation / tooling
HTML      → Human review
Markdown  → Documentation / writeups

Example:

python main.py scan \
    --target example.com \
    --full \
    --report json,html,markdown
Useful Commands
# Interactive mode
python main.py

# Check installation
python main.py check

# Configure API keys
python main.py config-wizard

# Resume interrupted scan
python main.py resume \
    --checkpoint path/to/checkpoint.json
Project Structure
GANDIV/
├── main.py
├── requirements.txt
├── README.md
├── .env.example
├── LICENSE
│
├── gandiv/
│   ├── config.py
│   ├── models.py
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
│   │   └── osint_aggregator.py
│   │
│   └── reporters/
│       ├── json_reporter.py
│       ├── html_reporter.py
│       └── markdown_reporter.py
│
└── tests/
    └── test_modules.py
Responsible Use

GANDIV is intended for:

Authorized security research
Bug bounty reconnaissance
Penetration testing
Threat intelligence
Defensive OSINT

Only scan targets you own or have explicit authorization to assess.

GANDIV uses publicly accessible information and does not bypass
authentication or access private systems.

Tech Stack
Python 3.11+
asyncio / aiohttp
ThreadPoolExecutor
Typer / Rich
dnspython
python-whois
Gemini
Jinja2
pytest
License

MIT License

<div align="center">
 ██████╗  █████╗ ███╗   ██╗██████╗ ██╗██╗   ██╗
██╔════╝ ██╔══██╗████╗  ██║██╔══██╗██║██║   ██║
██║  ███╗███████║██╔██╗ ██║██║  ██║██║██║   ██║
██║   ██║██╔══██║██║╚██╗██║██║  ██║██║╚██╗ ██╔╝
╚██████╔╝██║  ██║██║ ╚████║██████╔╝██║ ╚████╔╝
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═══╝

Reconnaissance, not surveillance.

</div> ```
