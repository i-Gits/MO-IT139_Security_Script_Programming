<!--- 
MO-IT142 Security Script Programming
PASSECURIST - Multi-Function Security Tool
BSIT-S31101: Delas Armas, J., Encillo, C., Samaniego, M., Tantoco, H.
Section 1: Header + Last Updated--->

# 🛡️ PASSECURIST
**A Comprehensive Security Toolkit**

<details>
<summary> 📅 Last Updated </summary>
<br>

| Date | Branch | Notes |
|------|--------|-------|
| March 2, 2026 | `milestone2-revised` | Added PCAP export, no-limit scanning, stop/pause/resume |
| February 24, 2026 | `milestone2` | Added Network Port Scanner, Traffic Analyzer |
| February 1, 2026 | `gui` | Migrated from Tkinter to Streamlit |
| January 27, 2026 | `ms1_draft` | Added SHA-256 hashing, security logger |

</details>

---

## 🔗 Quick Links

| Resource | Link |
|----------|------|
| Repository | [GitHub](https://github.com/i-Gits/MO-IT139_Security_Script_Programming.git) |
| Project Plan | [Google Sheets](https://docs.google.com/spreadsheets/d/1oXL5hJg6MRoZwp_r84P0JkorvVMnKP5bkcYPTfBOUP0/edit?usp=sharing) |
| Current Branch | `milestone2-revised` | AS OF MARCH 02, 2026 | 09:00:00 


---

## Features Overview

<details>
<summary> 1. Password Strength Analyzer </summary>
<br>

Analyzes password structure and flags weak passwords.

- Checks length, uppercase, lowercase, numbers, symbols
- Flags common passwords and dictionary words immediately
- Uses local dictionary file and optional NLTK corpus
- Visual strength indicator (Weak/Moderate/Strong)
- Generates SHA-256 hash of entered password

<details>
<summary> 📸 Screenshot </summary>
<br>

<!-- ![Password Strength Analyzer]() -->
*Screenshot pending*

Push note: pushed via VSCODE; no ubuildt in screenshot upload; in comparison, github query feature can be used as temp image upload and link generator

</details>

</details>

<details>
<summary> 2. Secure Password Generator </summary>
<br>

Cryptographically secure passwords with SHA-256 hashing.

- Generates cryptographically secure passwords (8-32 characters)
- Automatically includes all character types
- Creates SHA-256 hash with random salt
- **Security**: Raw passwords are NEVER saved to disk

<details>
<summary> 📸 Screenshot </summary>
<br>

<!-- ![Password Generator]() -->
*Screenshot pending*

</details>

</details>

<details>
<summary> 3. Web Form Validator </summary>
<br>

XSS and SQL injection detection with sanitization.

- Validates 4 fields: Full Name, Email, Username, Message
- Checks for SQL injection keywords and XSS patterns
- Email validation follows RFC 5321 standards
- Blocks disposable email domains
- Shows ALL violations per field with inline feedback
- Displays sanitized output for safe database storage

<details>
<summary> 📸 Screenshot </summary>
<br>

<!-- ![Web Form Validator]() -->
*Screenshot pending*

</details>

</details>

<details>
<summary> 4. Network Port Scanner </summary>
<br>

TCP port scanning with preset categories and real-time results.

- Scans a target host (IP or hostname) for open TCP ports
- Preset categories for quick port selection: Web, Mail, Remote Access, File Transfer, Network Core, Gaming (Steam, Valorant), and more
- Supports custom port ranges (1–65535, max 10,000 ports per scan)
- Real-time scan progress with live results table
- Stop/cancel scan mid-run without waiting for completion
- Identifies service names for discovered open ports
- Exports scan results as a CSV report
- Locks out Traffic Analyzer while a scan is active to prevent conflicts

<details>
<summary> 📸 Screenshot </summary>
<br>

<!-- ![Network Port Scanner]() -->
*Screenshot pending*

</details>

</details>

<details>
<summary> 5. Network Traffic Analyzer </summary>
<br>

Real-time packet capture with BPF filtering and export. Requires administrator/root privileges.

- Captures live network packets using Scapy
- BPF (Berkeley Packet Filter) support: filter by protocol, port, host, source IP, and destination IP
- MAC vendor lookup for source device identification
- Configurable packet limit (set to 0 for unlimited capture)
- Pause and Resume capture without losing previously captured packets
- Exports captured traffic as CSV or PCAP (compatible with Wireshark)
- Locks out Network Port Scanner while capture is active to prevent conflicts

<details>
<summary> 📸 Screenshot </summary>
<br>

<!-- ![Network Traffic Analyzer]() -->
*Screenshot pending*

</details>

</details>

---

# 🚀 How to Run

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
pip install streamlit pandas nltk scapy streamlit-keyup streamlit-option-menu cryptography

# 5. Run the app
streamlit run app.py

# 6. For Traffic Analyzer (requires admin):
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
pip install streamlit pandas nltk scapy streamlit-keyup streamlit-option-menu cryptography

# 5. Run the app
streamlit run app.py

# 6. For Traffic Analyzer (requires sudo):
sudo .venv/bin/python -m streamlit run app.py
```

</details>

<!-- <details>
<summary> 🐧 Linux </summary>
<br>

```bash
# 1. Clone the repository
git clone https://github.com/i-Gits/MO-IT139_Security_Script_Programming.git

# 2. Create virtual environment (Similar to MacOS)
python3 -m venv .venv

# 3. Activate virtual environment (Just like in the other two operating ssytems)
source .venv/bin/activate

# 4. Install dependencies
pip install streamlit pandas etc etc etc

# 5. Run the app
streamlit run app.py

# 6. For Traffic Analyzer (requires sudo):

to verify online/ask for guidance

```

</details>.  | -->

---

# 📁 Project Structure

<details>
<summary> 📂 File Tree </summary>
<br>

```
MO-IT139_Security_Script_Programming/
│
├── app.py                              # Streamlit main entry point with tabbed interface
├── README.md                           # Project documentation (you are here~r!)
│
├── data/
│   ├── dictionary.txt                  # Local word list for password strength checking (optional)
│   ├── passwords.txt                   # Hash storage (NO raw passwords saved)
│   └── security_log.txt                # Attack/sanitization event logs
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
│   │   └── network_traffic_analyzer.py # Packet capture with Scapy (requires sudo)
│   │
│   ├── gui/                            # Tkinter tabs (legacy, not used)
│   │   ├── password_strength_tab.py    # Strength analyzer interface (legacy)
│   │   ├── password_generator_tab.py   # Generator interface (legacy)
│   │   ├── webform_validator_tab.py    # Form validator interface (legacy)
│   │   ├── network_port_scanner_tab.py # Port scanner interface (legacy)
│   │   ├── network_traffic_analyzer_tab.py # Traffic analyzer interface (legacy)
│   │   └── styles.py                   # Application theme configuration (legacy)
│   │
│   └── utils/
│       ├── dictionary.py               # Dictionary loading (local + NLTK)
│       ├── genPassStorage.py           # Password hash storage (NO raw passwords)
│       └── security_logger.py          # Security event logging (attacks, sanitization)
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
| `src/features/password_generator.py` | Secure password generation + hashing |
| `src/features/webform_validator.py` | XSS/SQL injection detection |
| `src/features/network_port_scanner.py` | TCP port scanning |
| `src/features/network_traffic_analyzer.py` | Packet capture with Scapy |
| `src/utils/security_logger.py` | Attack/sanitization logging |
| `data/passwords.txt` | Hash storage (NO raw passwords) |
| `data/security_log.txt` | Audit trail |

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
| 5-6 | **Moderate** |
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
| **Username** | 4-16 chars, starts with letter, no spaces, only letters/numbers/underscores |
| **Message** | Max 250 chars, blocks SQL keywords & XSS patterns, logs attack attempts |

<details>
<summary> 🔍 Full Name Details </summary>

- Minimum 2 characters
- No numbers allowed
- Only letters, spaces, hyphens, apostrophes
- Allows single-space format only (✅"Mario Juan" | ❌"Mario__Juan")

</details>

<details>
<summary> 🔍 Email Details </summary>

- RFC 5321 compliant (max 320 chars)
- Valid structure: local@domain.tld
- No spaces, consecutive dots, or invalid characters
- Should not start with a special character
- Blocks disposable email domains
-* *RFC = Request for Comments; basically official internet rulebook for email formatting
w/c is 
Max 320 characters total
Local part (before @) max 64 chars
Domain (after @) max 255 chars
Valid characters allowed




</details>

<details>
<summary> 🔍 Username Details </summary>

- 4-16 characters
- Must start with letter
- No spaces allowed
- Only letters, numbers, underscores
- No consecutive underscores

</details>

<details>
<summary> 🔍 Message Details </summary>

- Max 250 characters
- Should not be empty
- Blocks SQL keywords (SELECT, DROP, etc.)
- Blocks XSS patterns (script tags, event handlers)
- Blocks JavaScript protocols
- Logs attack attempts (SQL injection, XSS) to security log

</details>

</details>

---

<details>
<summary> 🔍 Port Scanner Configuration </summary>
<br>

### Port Presets
| Category | Key Ports | Description |
|----------|-----------|-------------|
| Web Services | 80, 443 | HTTP and HTTPS |
| Mail Services | 25, 110, 143 | SMTP, POP3, IMAP |
| Remote Access & Management | 22, 23, 3389 | SSH, Telnet, RDP |
| Directory / Authentication | 88, 389, 464, 636 | Kerberos, LDAP, LDAPS |
| File Transfer & Sharing | 20, 21, 69, 445 | FTP, TFTP, SMB |
| Network Core | 53, 67, 68, 123 | DNS, DHCP, NTP |
| Network Management & Monitoring | 161 | SNMP |
| Communication, VoIP, and Chat | 194, 1720, 5060, 5061 | IRC, H.323, SIP |
| Legacy and Testing | 7, 23 | Echo, Telnet |
| Steam | 80, 443, 27000–27100 | Steam platform ports |
| Valorant | 80, 443, 7000–8000 | Valorant game ports |

*Yes, we added gaming ports. Priorities~*

### Custom Range Rules
- Both start and end ports must be integers (1–65535)
- Start port must be ≤ end port
- Maximum range: 10,000 ports per scan
- Single port (start == end) is allowed

</details>

---

<details>
<summary> 📡 Traffic Analyzer Filter Reference </summary>
<br>

### BPF Filter Fields
| Field | Accepted Input | Example |
|-------|----------------|---------|
| Protocol | tcp, udp, icmp, ip, arp, ip6 | `tcp` |
| Port | Any valid port number | `443` |
| General IP/Host | IP address or hostname | `192.168.1.1` |
| Source IP | IP address or hostname | `10.0.0.5` |
| Destination IP | IP address or hostname | `8.8.8.8` |

- Filters are combined with `and` (e.g., `tcp and port 80 and host 192.168.1.1`)
- Leave all fields empty to capture all traffic
- Hostnames are resolved to IPs automatically before capture starts

### MAC Vendor Lookup
Detected source vendors include: VMware, Microsoft (Hyper-V), Google, Apple, Intel, Cisco. Unrecognized MACs display as "Generic Device".

</details>

---

<details>
<summary> 🔒 Security Features </summary>
<br>

<details>
<summary> Password Generator </summary>

- ✓ Cryptographically secure random generation
- ✓ SHA-256 hashing with 16-byte random salt
- ✓ Raw passwords NEVER saved to disk
- ✓ Hash storage in `data/passwords.txt`
- ✓ Copy functions for easy password management

</details>

<details>
<summary> Password Strength Analyzer </summary>

- ✓ Dictionary word detection (local + NLTK)
- ✓ Common password veto system
- ✓ Visual strength indicators
- ✓ SHA-256 hash generation for analysis
- ✓ Detailed feedback on weaknesses

</details>

<details>
<summary> Web Form Validator </summary>

- ✓ Multi-layer sanitization (9 layers)
- ✓ SQL injection keyword filtering
- ✓ XSS pattern detection and removal
- ✓ HTML entity escaping
- ✓ Inline validation with ALL violations shown
- ✓ Disposable email domain blocking
- ✓ Security logging system


<details>
<summary> Extra Tid Bits of Info ℹ️ </summary>

RFC 5321 = email format rules (industry standard)
SQL injection = attacks database with SQL commands
XSS = attacks browser with scripts
Both are logged in security_log.txt


</details>
</details>

<details>
<summary> Network Port Scanner </summary>

- ✓ TCP socket-based port scanning
- ✓ Host validation before scan starts (resolves hostname to IP)
- ✓ Configurable timeout per port (default: 0.5s)
- ✓ Cancel-safe: scan thread checks for stop signal between each port
- ✓ Results exported as timestamped CSV

</details>

<details>
<summary> Network Traffic Analyzer </summary>

- ✓ Privilege check before capture starts (blocks unprivileged runs)
- ✓ BPF filter validation before applying to Scapy
- ✓ Raw packets stored in memory for accurate PCAP export
- ✓ Ping timeout safeguard: auto-stops capture after 30s of inactivity
- ✓ Tool mutex: Port Scanner and Traffic Analyzer cannot run simultaneously

</details>

</details>

---

<details>
<summary> 💾 Data Storage </summary>
<br>

<details>
<summary> Generated Passwords (data/passwords.txt) </summary>

**Format:** `[timestamp] | hash # salt`
- Stores hash and salt only
- NO raw passwords saved
- Append mode (previous entries preserved)

</details>

<details>
<summary> Security Logs (data/security_log.txt) </summary>

**Format:** Timestamped entries with detailed event information
- Logs attack attempts (SQL injection, XSS, disposable emails)
- Records sanitization actions
- Tracks validation summaries
- Append mode (audit trail preserved)

</details>

</details>

---

<details>
<summary> 📦 Dependencies </summary>
<br>

**Built-in (no install needed):**
```
hashlib, os, re, html, string, random, datetime, socket, struct
```

**Install required:**
```bash
pip install streamlit pandas nltk scapy streamlit-keyup streamlit-option-menu cryptography
```

| Package | Purpose |
|---------|---------|
| `streamlit` | Web UI framework |
| `pandas` | Data handling for tables |
| `nltk` | Extended dictionary (optional) |
| `scapy` | Packet capture (Traffic Analyzer) |
| `streamlit-keyup` | Real-time input detection |
| `streamlit-option-menu` | Navigation menu |
| `cryptography` | Encryption features |

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
| **MS2-revised** | Mar 2, 2026 | PCAP export, no-limit scanning, pause/resume, BPF filters, src/dst IP filtering, process termination fixes |

<details>
<summary> MS1 Details </summary>

**Core Features (Jan 26, 2026):**
- Password Strength Analyzer with 7-point scoring system
- Password Generator & Hasher with SHA-256
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
- Network Port Scanner with TCP scanning
- Network Traffic Analyzer with Scapy

**Revisions (Mar 2, 2026):**
- PCAP export functionality
- No-limit packet capture option
- Pause/Resume controls
- BPF filter support
- Source/Destination IP filtering
- Fixed process termination on tab/menu switch
- Fixed scan stop/cancel event handling
- Fixed capture ping timeout safeguard

</details>

</details>

---

<details>
<summary> 📝 Notes </summary>
<br>

| Topic | Note |
|-------|------|
| **NLTK** | Optional — app works without it but has smaller dictionary |
| **Raw passwords** | NEVER stored in password generator; and it shouldn't be! Be careful|
| **Security logs** | All validation events logged to `data/security_log.txt` |
| **User privacy** | Users only see clean error messages, not detailed logs ~ as it should be|
| **Traffic Analyzer** | Requires sudo (macOS/Linux) or Admin (Windows) |
| **Tool Conflicts** | Port Scanner and Traffic Analyzer cannot run at the same time — one locks the other |

</details>

---

<details>
<summary> 📋 Group's Project Plan </summary>
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