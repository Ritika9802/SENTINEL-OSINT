# Sentinel OSINT

A Streamlit-based Open Source Intelligence (OSINT) platform for investigating domains, IPs, usernames, hashes, files, and security-related signals from a single analyst workspace.

## Features

- **IP / Domain Reputation** — VirusTotal, Shodan, AbuseIPDB, and threat scoring
- **TLS / SSL Intelligence** — certificate details, issuer, expiry, and SANs
- **DNS Intelligence** — DNS and infrastructure lookups
- **Passive Subdomain Discovery** — Certificate Transparency and other passive sources
- **Typosquatting Analysis** — lookalike domain generation with DNSTwist fallback
- **Username Hunt** — Sherlock-based username discovery
- **Network Graph** — visualize relationships between domains, IPs, and ports
- **Hash Tools** — generate and verify common cryptographic hashes
- **Metadata Inspector** — inspect metadata from supported files
- **Password Security** — password-strength/security utilities
- **Cybersecurity News** — security news feed
- **Security Support Hub** — security resources and support information

## Tech Stack

- Python
- Streamlit
- Requests
- Python-dotenv
- DNSTwist
- Sherlock
- PyVis
- Pillow
- pypdf
- python-docx
- Mutagen
- Feedparser

## Project Structure

```text
.
├── app.py
├── requirements.txt
├── .env.example
├── .gitignore
├── assets/
├── modules/
└── utils/
```

## Setup

### 1. Clone the repository

```bash
git clone <your-repository-url>
cd Sentinel-OSINT
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

Activate it:

**Windows**
```bash
.venv\Scripts\activate
```

**macOS / Linux**
```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API keys

Copy `.env.example` to `.env` and add your own API keys.

```bash
copy .env.example .env
```

Do **not** commit `.env` or real API keys to GitHub.

### 5. Run the application

```bash
streamlit run app.py
```

## Security Note

This project is intended for legitimate security research, OSINT, defensive analysis, and authorized investigations. Only investigate systems and accounts you are authorized to assess.

## Portfolio Highlights

This project demonstrates:

- API integration and external data aggregation
- OSINT workflow design
- Python modular application architecture
- Streamlit UI development
- Threat/risk scoring
- Passive reconnaissance techniques
- Data parsing and normalization
- Security-focused tooling

## License

Add the license you want to use for this project before publishing.
