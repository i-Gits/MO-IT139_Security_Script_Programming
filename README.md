<!--- 
MO-IT142 Security Script Programming
PASSECURIST - Multi-Function Security Tool
BSIT-S31101: Delas Armas, J., Encillo, C., Samaniego, M., Tantoco, H.
--->

# 🛡️ PASSECURIST
**A Comprehensive Security Toolkit**

## Quick Start
Requirements: Python 3.8+, macOS/Windows/Linux. For network tools, run as admin/sudo.

For network features (Traffic Analyzer, Port Scanner), use `sudo` or run as Administrator.

Data: Password hashes are saved in the `data/` folder.

<details>
<summary> 📅 Last Updated </summary>
<br>

| Date | Branch | Notes |
|------|--------|-------|
| March 28, 2026 | `main` | Updated Documentation.md and README.md |
| March 26, 2026 | `main` | Merged `ta-draft` to main; bug fixes, Password Strength per-check pass messages |
| March 23, 2026 | `ta-draft` | URL Expander, URL Scam Scanner, Port Vulnerability DB, expanded test coverage |
| March 8, 2026  | `ms2-dataviz` | Plotly visualizations, traceroute graph, cross-platform gateway detection |
| March 2, 2026  | `milestone2-revised` | PCAP export, no-limit scanning, pause/resume, BPF filters |
| February 24, 2026 | `milestone2` | Added Network Port Scanner, Traffic Analyzer |
| February 1, 2026  | `gui` | Migrated from Tkinter to Streamlit |
| January 27, 2026  | `ms1_draft` | Added SHA-256 hashing, security logger |

</details>

---

## 🔗 Quick Links

| Resource | Link |
|----------|------|
| Repository | [GitHub](https://github.com/i-Gits/MO-IT139_Security_Script_Programming.git) |
| Project Plan & Documentation Sheet | [Google Sheets](https://docs.google.com/spreadsheets/d/1oXL5hJg6MRoZwp_r84P0JkorvVMnKP5bkcYPTfBOUP0/edit?usp=sharing) |
| Current Branch | `main` |

---

## Features Overview

<details>
<summary> Home Screen </summary>
<img width="1080" height="679" alt="image" src="https://github.com/user-attachments/assets/0bb2490b-bd50-43a8-bc52-a4b5fd2cf432" />
</details>

---

### 🌐 Web Based Security Tools

<details>
<summary> 1. Password Strength Analyzer </summary>
<br>

Analyzes password structure and flags weak passwords in real time.

- Checks length, uppercase, lowercase, numbers, and special characters
- Each passing check now displays its own individual ✅ message
- Flags common passwords and dictionary words immediately (automatic WEAK)
- Uses local dictionary file and optional NLTK corpus
- Visual strength indicator (Weak / Moderate / Strong) with progress bar
- Generates SHA-256 hash of the entered password

<details>
<summary> 📸 Screenshot </summary>
<br>

<img width="843" height="621" alt="image" src="https://github.com/user-attachments/assets/cbe39861-afce-44c6-9bec-35fe6eb18cf5" />
<br><br>
<img width="859" height="662" alt="image" src="https://github.com/user-attachments/assets/fd043b89-9ef7-421d-85c4-47a3f43b9fb6" />

</details>
</details>

<details>
<summary> 2. Secure Password Generator </summary>
<br>

Cryptographically secure password generation with SHA-256 hashing.

- Generates cryptographically secure passwords (8–32 characters)
- Automatically includes all character types (uppercase, lowercase, digits, symbols)
- Creates SHA-256 hash with 16-byte random salt
- Save hash to `data/passwords.txt` for audit purposes
- **Security**: Raw passwords are NEVER saved to disk

<details>
<summary> 📸 Screenshot </summary>
<br>

<img width="835" height="558" alt="image" src="https://github.com/user-attachments/assets/3004ac35-6a56-4385-8dfa-9b7968433e80" />
<br><br>
<img width="846" height="830" alt="image" src="https://github.com/user-attachments/assets/ada682ac-1e12-4bc5-b897-5828ca5f87ad" />

</details>
</details>

<details>
<summary> 3. Web Form Validator </summary>
<br>

XSS and SQL injection detection with multi-layer sanitization.

- Validates 4 fields: Full Name, Email, Username, Message
- Checks for SQL injection keywords and XSS patterns
- Email validation follows RFC 5321 standards
- Blocks disposable email domains (yopmail, mailinator, etc.)
- Shows ALL violations per field with inline feedback (not just the first error)
- Displays sanitized output for safe database storage

<details>
<summary> 📸 Screenshot </summary>
<br>

<img width="901" height="674" alt="image" src="https://github.com/user-attachments/assets/7a59b0d5-87c6-4044-86c3-36b06aa2fc42" />
<br><br>
<img width="1822" height="945" alt="Image" src="https://github.com/user-attachments/assets/6d14501c-98ed-45f3-8a46-3c5932ee5ed6" />


</details>
</details>

<details>
<summary> 4. URL Expander </summary>
<br>

Reveal the real destination behind shortened URLs without visiting them.

- Follows all HTTP redirects and returns the final resolved URL
- Supports most major URL shorteners (bit.ly, TinyURL, t.co, etc.)
- Handles invalid or unreachable URLs with user-friendly error messages
- Tested with TinyURL, Bitly, and invalid links — all passed ✓

<details>
<summary> 📸 Screenshot </summary>
<br>

<img width="947" height="626" alt="Image" src="https://github.com/user-attachments/assets/a281f737-956f-4a49-bfb4-b9678988fbbf" />
<br><br>
<img width="888" height="677" alt="Image" src="https://github.com/user-attachments/assets/e4e6ea30-6a1c-408c-9218-d4882c81691b" />


</details>
</details>

<details>
<summary> 5. URL Scam Scanner </summary>
<br>

Analyze URLs for phishing and scam indicators using offline heuristic rules.

- 8-rule risk scoring system (IP as domain, typosquatting, suspicious TLDs, brand impersonation, URL shorteners, open redirects, etc.)
- Severity-weighted scoring: HIGH (3 pts), MEDIUM (2 pts), LOW (1 pt)
- Color-coded verdict: 🚨 Likely Malicious / ⚠️ Suspicious / ✅ Safe
- Explains each triggered flag in plain language
- When a URL shortener is detected, prompts user to use the URL Expander first
- Works fully offline — no data is sent externally
- Tested with safe, suspicious, and shortened URLs — all passed ✓

<details>
<summary> 📸 Screenshot </summary>
<br>

<img width="658" height="207" alt="image" src="https://github.com/user-attachments/assets/6d29f6c3-7f02-41da-9721-794ea2da72ba" />
<br><br>
<img width="516" height="670" alt="Image" src="https://github.com/user-attachments/assets/da0b4e37-909d-4aa6-9232-b0163c08d6b0" />

</details>
</details>

---

### 💻 Local Security Tools

<details>
<summary> 6. Network Port Scanner </summary>
<br>

TCP port scanning with preset categories, real-time results, vulnerability checking, and data visualization.

- Scans a target host (IP or hostname) for open TCP ports
- Preset categories: Web, Mail, Remote Access, File Transfer, Network Core, Directory/Auth, Gaming (Steam, Valorant), and more
- Supports custom port ranges (1–65535, max 10,000 ports per scan)
- Real-time scan progress with live results table
- Stop/cancel scan mid-run without waiting for completion
- Identifies service names for discovered open ports
- Exports scan results as CSV

**Port Vulnerability Check** (after each scan):
- Live CVE lookup from NVD via `nvdlib`
- IANA service name and description per port
- CVSS-based risk levels: CRITICAL / HIGH / MEDIUM / LOW
- Clicking ↗ View on a CVE opens the full NIST NVD page
- Clicking View port XX on ScaniteX ↗ opens the Port Encyclopedia for that port

**Scan Analysis** (interactive Plotly charts):
- KPI stat cards: Ports Scanned, Open Ports, Closed Ports, Scan Duration
- Open vs Closed donut chart
- Open Ports by Service Category bar chart
- Discovered Open Ports number line / spike chart

**Network Path — Traceroute**:
- Scapy-based traceroute with auto-detected gateway MAC (Windows/macOS/Linux)
- Interactive Plotly network path graph (cyan = you, blue = hops, green = target)
- KPI cards: Total Hops, Target Reached, No-Response Hops, Final RTT
- Hop detail table (IP, hostname, RTT, ICMP type, status)
- Requires admin/sudo privileges

<details>
<summary> 📸 Screenshot </summary>
<br>

<img width="1000" height="670" alt="image" src="https://github.com/user-attachments/assets/a21a89c6-f165-48eb-ba26-9e085b546f2c" />
<br><br>
<img width="1897" height="873" alt="Image" src="https://github.com/user-attachments/assets/2691607d-b273-4800-b86a-90ff1aacd731" />
<br><br>
<img width="1862" height="877" alt="Image" src="https://github.com/user-attachments/assets/e6a8a7a4-94ba-4d83-812d-a52808803369" />
<br><br>
<img width="1862" height="822" alt="Image" src="https://github.com/user-attachments/assets/5433fe32-86a2-4e49-b147-51410a4222c0" />
<br><br>
<img width="1907" height="908" alt="Image" src="https://github.com/user-attachments/assets/1666332d-6f8b-4e3c-86f6-ca2a66416b44" />
<br><br>
<img width="1797" height="560" alt="Image" src="https://github.com/user-attachments/assets/443d0edf-5ce9-493c-b37b-d686cd322449" />

</details>
</details>

<details>
<summary> 7. Network Traffic Analyzer </summary>
<br>

Real-time packet capture with BPF filtering, export, and data visualization. Requires administrator/root privileges.

- Captures live network packets using Scapy
- BPF filter support: filter by protocol, port, host, source IP, and destination IP
- Quick filter buttons: TCP, UDP, ICMP, HTTP, HTTPS, DNS
- MAC vendor lookup for source device identification
- Configurable packet limit (0 = unlimited)
- Pause and Resume capture without losing previously captured packets
- Exports captured traffic as CSV or PCAP (Wireshark-compatible)
- Locks out Network Port Scanner while capture is active (and vice versa)

**Traffic Analysis** (interactive Plotly charts, shown after pausing/stopping):
- KPI stat cards: Total Packets, Unique Sources, Unique Destinations, Top Protocol
  - Unique Sources/Destinations correctly exclude N/A entries from Unknown/ARP packets
- Protocol Distribution donut chart
- Top 8 Source IPs (Talkers) bar chart
- Top 10 Destination Ports treemap
- Packet Volume Over Time line/area chart
- Source Device Vendor Breakdown donut chart (when vendor data is available)

<details>
<summary> 📸 Screenshot </summary>
<br>

<img width="949" height="636" alt="image" src="https://github.com/user-attachments/assets/d8d260b9-d634-41af-b8b3-c995d4a5f8d0" />
<br><br>
<img width="1847" height="863" alt="Image" src="https://github.com/user-attachments/assets/a80e5f72-49a7-4de2-892e-d99f5e969e02" />
<br><br>
<img width="1867" height="813" alt="Image" src="https://github.com/user-attachments/assets/265290ae-977e-4e77-b1b8-2e3e0176f100" />


</details>
</details>

---

## 🚀 How to Run

<details>
<summary> 💻 Windows </summary>
<br>

```bash
# 1. Clone the repository
git clone https://github.com/i-Gits/MO-IT139_Security_Script_Programming.git

# 2. Create virtual environment
python -m venv .venv

# 3. Activate virtual environment
.venv\Scripts\activate

# 4. Install dependencies
pip install streamlit pandas nltk scapy streamlit-keyup streamlit-option-menu cryptography plotly nvdlib requests

# 5. Run the app
streamlit run app.py

# 6. For Traffic Analyzer and Traceroute (requires admin):
#    - Open PowerShell as Administrator
#    - Navigate to project folder
#    - Run: .venv\Scripts\python -m streamlit run app.py
```

</details>

<details>
<summary> 🍎 macOS </summary>
<br>

```bash
# 1. Clone the repository
git clone https://github.com/i-Gits/MO-IT139_Security_Script_Programming.git

# 2. Create virtual environment
python3 -m venv .venv

# 3. Activate virtual environment
source .venv/bin/activate

# 4. Install dependencies
pip install streamlit pandas nltk scapy streamlit-keyup streamlit-option-menu cryptography plotly nvdlib requests

# 5. Run the app
streamlit run app.py

# 6. For Traffic Analyzer and Traceroute (requires sudo):
sudo .venv/bin/python -m streamlit run app.py
```

</details>

---

## 📁 Project Structure

<details>
<summary> 📂 File Tree </summary>
<br>

```
MO-IT139_Security_Script_Programming/
│
├── app.py                              # Streamlit main entry point with tabbed interface
├── README.md                           # Project documentation (you are here~!)
│
├── data/
│   ├── dictionary.txt                  # Local word list for password strength checking (optional)
│   ├── passwords.txt                   # Hash storage (NO raw passwords saved)
│   └── security_log.txt                # Attack/sanitization event logs (legacy, not used)
│
├── docs/
│   └── Documentation.md                # Technical documentation
│
├── src/
│   ├── main.py                         # Tkinter entry point (legacy, not used)
│   │
│   ├── features/
│   │   ├── password_strength.py        # Password evaluation logic with veto checks
│   │   ├── password_generator.py       # Secure password generation + SHA-256 hashing
│   │   ├── webform_validator.py        # Form validation with XSS/SQL injection detection
│   │   ├── network_port_scanner.py     # TCP port scanning logic
│   │   ├── network_traffic_analyzer.py # Packet capture with Scapy (requires sudo)
│   │   ├── url_expander.py             # URL expansion (shortener reveal)
│   │   └── url_scam_scanner.py         # Offline URL scam/phishing scanner
│   │
│   ├── gui/                            # Tkinter tabs (legacy, not used)
│   │   ├── password_strength_tab.py
│   │   ├── password_generator_tab.py
│   │   ├── webform_validator_tab.py
│   │   ├── network_port_scanner_tab.py
│   │   ├── network_traffic_analyzer_tab.py
│   │   └── styles.py
│   │
│   └── utils/
│       ├── dictionary.py               # Dictionary loading (local + NLTK)
│       ├── genPassStorage.py           # Password hash storage (NO raw passwords)
│       ├── security_logger.py          # Security event logging (attacks, sanitization) (used by legacy Tkinter GUI only)
│       └── port_vulnerability_db.py    # Port risk data, CVE lookups, Plotly visualizations
│
└── assets/
    └── screenshots/                    # UI screenshots
```

</details>

<details>
<summary> 📄 Key Files Explained </summary>
<br>

| File | Purpose |
|------|---------|
| `app.py` | Streamlit main entry point |
| `src/main.py` | Tkinter entry (legacy) |
| `src/features/password_strength.py` | Password evaluation with veto checks |
| `src/features/password_generator.py` | Secure password generation + SHA-256 hashing |
| `src/features/webform_validator.py` | XSS/SQL injection detection and sanitization |
| `src/features/network_port_scanner.py` | TCP port scanning logic |
| `src/features/network_traffic_analyzer.py` | Packet capture with Scapy |
| `src/features/url_expander.py` | URL expansion (shortener reveal) |
| `src/features/url_scam_scanner.py` | Offline URL scam/phishing scanner |
| `src/utils/port_vulnerability_db.py` | Port risk data, CVE lookups, Plotly visualizations |
| `data/passwords.txt` | Hash storage (NO raw passwords) |

</details>

---

<details>
<summary> 🔐 Password Strength Evaluation </summary>
<br>

### Structural Checks (5 points)
1. Length ≥ 12 characters
2. Contains uppercase letter
3. Contains lowercase letter
4. Contains number
5. Contains special character

### Veto Checks (2 bonus points)
1. Not in common passwords list
2. Contains no dictionary words

**Scoring:**
| Score | Rating |
|-------|--------|
| 7 | **Strong** (all checks passed, no veto) |
| 5–6 | **Moderate** |
| ≤4 OR vetoed | **Weak** |

</details>

---

<details>
<summary> 📝 Web Form Validation Rules </summary>
<br>

| Field | Rules |
|-------|-------|
| **Full Name** | Min 2 chars, no numbers, only letters/spaces/hyphens/apostrophes, single-space only |
| **Email** | RFC 5321 compliant (max 320 chars), valid structure, blocks disposable domains |
| **Username** | 4–16 chars, starts with letter, no spaces, only letters/numbers/underscores, no consecutive underscores |
| **Message** | Max 250 chars, blocks SQL keywords & XSS patterns |

</details>

---

<details>
<summary> 🔒 Security Features </summary>
<br>

**Password Generator**
- ✓ Cryptographically secure random generation (`os.urandom`)
- ✓ SHA-256 hashing with 16-byte random salt
- ✓ Raw passwords NEVER saved to disk
- ✓ Hash + salt stored in `data/passwords.txt`

**Password Strength Analyzer**
- ✓ Dictionary word detection (local + NLTK)
- ✓ Common password veto (automatic WEAK)
- ✓ Individual ✅ pass messages per check
- ✓ SHA-256 hash generation for entered password

**Web Form Validator**
- ✓ 9-layer message sanitization
- ✓ SQL injection keyword filtering
- ✓ XSS pattern detection and removal
- ✓ HTML entity escaping
- ✓ Disposable email domain blocking
- ✓ Users see only clean pass/fail messages

**URL Scam Scanner**
- ✓ 8 offline heuristic rules
- ✓ Typosquatting detection (Levenshtein distance)
- ✓ Brand impersonation detection (30+ known brands)
- ✓ No external requests — fully offline

</details>

---

<details>
<summary> 💾 Data Storage </summary>
<br>

**Generated Passwords (`data/passwords.txt`)**

Format: `[timestamp] | hash # salt`
- Stores hash and salt only — NO raw passwords
- Append mode (previous entries preserved)

**Security Logs (`data/security_log.txt`)**

> ⚠️ *Used by the legacy Tkinter GUI only — not active in the Streamlit app.*

</details>

---

<details>
<summary> 📦 Libraries </summary>
<br>

**Built-in (no install needed):**

| Library | Purpose |
|---------|---------|
| `hashlib` | Hashing and cryptography |
| `os` | Operating system functions |
| `re` | Regular expressions |
| `html` | HTML handling and escaping |
| `string` | String utilities |
| `random` | Random number generation |
| `datetime` | Date and time utilities |
| `socket` | Network connections |
| `struct` | Binary data packing/unpacking |
| `sys` | System-specific parameters |
| `threading` | Multi-threading support |
| `time` | Time utilities |
| `platform` | Platform/OS detection |
| `ipaddress` | IP address manipulation |
| `subprocess` | Running system commands |
| `urllib.parse` | URL parsing |

**External (install required):**

| Package | Purpose |
|---------|---------|
| `streamlit` | Web UI framework |
| `pandas` | Data handling for tables |
| `nltk` | Extended dictionary (optional) |
| `scapy` | Packet capture (Traffic Analyzer, Traceroute) |
| `streamlit-keyup` | Real-time input detection |
| `streamlit-option-menu` | Navigation menu |
| `plotly` | Interactive data visualization |
| `cryptography` | Encryption features |
| `nvdlib` | NVD CVE API client (Port Vulnerability Check) |
| `requests` | HTTP requests (URL Expander) |

</details>

---

<details>
<summary> 📜 Version History </summary>
<br>

| Version | Date | Changes |
|---------|------|---------|
| **MS1 (Draft)** | Jan 26, 2026 | Password Strength Analyzer, Password Generator, Web Form Validator |
| **MS1 (Final)** | Jan 27, 2026 | Bug fixes, security logging system |
| **MS2 (GUI)** | Feb 1, 2026 | Migrated from Tkinter to Streamlit |
| **MS2** | Feb 24, 2026 | Added Network Port Scanner, Traffic Analyzer |
| **MS2 (Revisions)** | Mar 2, 2026 | PCAP export, no-limit scanning, pause/resume, BPF filters |
| **MS2 (Data Viz)** | Mar 8, 2026 | Plotly visualizations, traceroute graph, cross-platform gateway detection |
| **TA (Draft)** | Mar 23, 2026 | URL Expander, URL Scam Scanner, Port Vulnerability DB |
| **TA (Updates)** | Mar 26, 2026 | Merged ta-draft to main, bug fixes, Password Strength per-check pass messages |
| **TA (Final)** | Mar 28, 2026 | Updated Documentation.md and README.md |

<details>
<summary> MS1 Details </summary>

**Core Features (Jan 26, 2026):**
- Password Strength Analyzer with 7-point scoring system
- Password Generator & Hasher with SHA-256 + random salt
- Web Form Validator & Sanitizer with XSS/SQL injection protection

**Bug Fixes (Jan 27, 2026):**
- Fixed duplicate space error in username validation
- Improved error message display (quoted special characters)
- Strict single-space formatting for full names
- Implemented security logging system

</details>

<details>
<summary> MS2 Details </summary>

**Network Features (Feb 24, 2026):**
- Network Port Scanner with TCP scanning, presets, and CSV export
- Network Traffic Analyzer with Scapy — live capture, BPF filters

**Revisions (Mar 2, 2026):**
- PCAP export functionality (Wireshark-compatible)
- No-limit packet capture (count = 0)
- Pause/Resume controls
- BPF filter support (protocol, port, host, source IP, destination IP)

**Data Visualization (Mar 8, 2026):**
- Plotly charts integrated into Port Scanner and Traffic Analyzer tabs
- Traceroute with interactive network path graph
- Cross-platform gateway detection (Windows, macOS, Linux)
- KPI stat cards for both tools

</details>

<details>
<summary> TA Details </summary>

**Terminal Assessment Draft (Mar 23, 2026):**

*URL Expander:*
- Backend: HTTP HEAD requests to follow redirects, handles invalid/unreachable URLs
- GUI: Streamlit tab with input, Expand button, result display, error feedback
- Testing: Verified with TinyURL, Bitly, invalid links — all passed

*URL Scam Scanner:*
- Backend: 8 offline heuristic rules (IP as domain, typosquatting, brand impersonation, suspicious TLDs, URL shorteners, open redirects, excessive hyphens, no HTTPS)
- GUI: Color-coded verdict, per-flag detail cards, URL shortener cross-tool prompt
- Testing: Verified with safe, scam, and shortened URLs — all passed

*Port Scanner — Port Vulnerability DB:*
- Backend: `port_vulnerability_db.py` with IANA lookup, NVD CVE fetching (`nvdlib`), CVSS-based risk scoring
- GUI: `render_vulnerability_section()` called automatically after each scan
- ↗ View on a CVE → NIST NVD page
- View port XX on ScaniteX ↗ → Port Encyclopedia for that port

**Terminal Assessment Final (Mar 26, 2026):**
- Merged `ta-draft` to `main`

*Password Strength Analyzer:*
- Each passing check now stores and displays an individual ✅ success message
- Replaces the previous single generic "Excellent!" success message

**Documentation (Mar 28, 2026):**
- Updated `Documentation.md` and `README.md`

</details>

</details>

---

<details>
<summary> 📝 Notes </summary>
<br>

| Topic | Note |
|-------|------|
| **NLTK** | Optional — app works without it but uses a smaller dictionary |
| **Raw passwords** | NEVER stored; hash + salt only. Be careful! |
| **User privacy** | Users only see clean pass/fail messages in the Streamlit app |
| **Traffic Analyzer** | Requires sudo (macOS/Linux) or Admin (Windows) |
| **Traceroute** | Also requires sudo/Admin — uses Scapy for packet crafting |
| **Port Vulnerability** | Requires internet access for live NVD CVE lookups |

</details>

---

<details>
<summary> 📋 Group's Project Plan & Documentation Sheet </summary>
<br>

**[View on Google Sheets](https://docs.google.com/spreadsheets/d/1oXL5hJg6MRoZwp_r84P0JkorvVMnKP5bkcYPTfBOUP0/edit?usp=sharing)**

| Member | Role |
|--------|------|
| C. Encillo | Developer / Quality Assurance |
| H. Tantoco | Developer / QA / Documentation |
| J. Delas Armas | Developer / QA / Documentation |
| M. Samaniego | Developer / Quality Assurance |

</details>

---

*BSIT-S31101 | MO-IT139 Security Script Programming | 2026*