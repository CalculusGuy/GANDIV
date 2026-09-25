<div align="center">

```text
 ██████╗  █████╗ ███╗   ██╗██████╗ ██╗██╗   ██╗
██╔════╝ ██╔══██╗████╗  ██║██╔══██╗██║██║   ██║
██║  ███╗███████║██╔██╗ ██║██║  ██║██║██║   ██║
██║   ██║██╔══██║██║╚██╗██║██║  ██║██║╚██╗ ██╔╝
╚██████╔╝██║  ██║██║ ╚████║██████╔╝██║ ╚████╔╝
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═══╝

Multi-Source OSINT Reconnaissance Engine

Collect signals. Correlate evidence. Reduce noise. Produce intelligence.

</div>
Overview

GANDIV is an OSINT reconnaissance engine that automates the information-gathering phase of a security assessment.

It supports targets such as:

Domain
Email
Phone number
Username
IP address
URL
Name

GANDIV collects findings from multiple sources, normalizes and deduplicates them, applies confidence scoring, and generates structured reports.

Workflow
Features
Multi-source OSINT reconnaissance
Domain, web and infrastructure recon
Email and phone OSINT
Username and person enumeration
Finding normalization and deduplication
Confidence scoring
Optional Gemini analysis
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

Start GANDIV:

python main.py
User Guide
Interactive Mode

Run:

python main.py

Then choose a module:

Option	Module	Purpose
1	People OSINT	Email, phone, username, name
2	Domain Recon	Subdomains, DNS, WHOIS, certificates
3	Web Recon	Technology, WAF, headers, JS
4	Infrastructure	IP, ASN, Shodan, Censys, SSL
5	Breach & Leak	HIBP and paste sources
6	Username	Multi-platform enumeration
7	Reverse Image	Image and EXIF analysis
8	Full OSINT	Run available modules
9	Custom Scan	Select modules manually
CLI Usage
Domain
python main.py scan --target example.com --type domain --full
Email
python main.py scan \
    --target user@example.com \
    --type people-email
Phone
python main.py scan \
    --target +919999999999 \
    --type people-phone
Username
python main.py scan \
    --target johndoe \
    --type people-username
Full Scan
python main.py scan \
    --target example.com \
    --full \
    --report json,html,markdown
Reports

Reports are generated inside gandiv_reports/.

Format	Use
JSON	Automation, CI/CD and tooling
HTML	Human review and presentations
Markdown	Documentation and writeups
API Configuration

API keys are optional. Additional integrations can increase coverage.

Run:

python main.py config-wizard

Or configure .env manually:

GEMINI_API_KEY=your_key_here

Supported integrations include:

Gemini
HIBP
Shodan
Censys
GitHub
VirusTotal
Numverify
Useful Commands
Command	Purpose
python main.py	Interactive mode
python main.py check	Check environment
python main.py config-wizard	Configure API keys
python main.py resume --checkpoint <file>	Resume a scan
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
Tech Stack
Layer	Technology
Language	Python 3.11+
Async	asyncio, aiohttp
Concurrency	ThreadPoolExecutor
CLI	Typer, Rich
DNS	dnspython
WHOIS	python-whois
AI	Gemini
Reporting	Jinja2, JSON, Markdown
Testing	pytest
Responsible Use

GANDIV is intended for authorized security research and defensive intelligence.

Only use it against systems or targets you own or have explicit authorization to assess.

Do not use GANDIV for:

Unauthorized scanning
Surveillance of individuals
Circumventing security controls
Violating privacy or data-protection laws

GANDIV works with publicly accessible information and does not bypass authentication or access private systems.

License

MIT License. See LICENSE.

<div align="center">

GANDIV

Reconnaissance, not surveillance.

Never Miss Target Intelligence.

</div> ```
