# 📚 Technical Documentation
**PASSECURIST - Security Script Programming**

> *Welcome~!*

---

<details>
<summary> 📂 Project Structure </summary>
<br>

```
MO-IT139_Security_Script_Programming/
│
├── app.py                              # Streamlit main entry point with tabbed interface
├── README.md                           # Project documentation (Comprehensive)
│
├── data/
│   ├── dictionary.txt                  # Local word list for password strength checking (optional)
│   ├── passwords.txt                   # Hash storage (NO raw passwords saved)
│   └── security_log.txt                # Attack/sanitization event logs (legacy, not used)
│
├── docs/
│   └── Documentation.md                # Technical documentation (you are here~!)
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
│   │   ├── url_expander.py             # Expands shortened URLs to their true destination
│   │   └── url_scam_scanner.py         # Offline phishing/scam URL detection
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
│       ├── security_logger.py          # Security event logging (used by legacy Tkinter GUI only)
│       └── port_vulnerability_db.py    # Port risk data, CVE lookups, and data visualization backend
│
└── assets/
    └── screenshots/                    # UI screenshots
```

*`app.py` is the main entry point for the Streamlit version. The `gui/` folder and `security_logger.py` are used by the legacy Tkinter version only and are not called by `app.py`.*

</details>

---

<details>
<summary> 🔐 Password Strength Analyzer </summary>
<br>

Analyzes password strength using structural and veto checks, with instant real-time feedback. Integrated into the Streamlit GUI via `app.py`.

**File**: `src/features/password_strength.py`

**Used by `app.py`**:
```python
from features.password_strength import evaluate_password_strength
```

---

### evaluate_password_strength(password)
**Purpose**: Main password assessment function that tests password strength and provides detailed feedback.

**Parameters**:
- `password` (str): The password to evaluate

**Returns**: Tuple of `(rating, color, messages)`
- `rating` (str): `"WEAK"`, `"MODERATE"`, or `"STRONG"`
- `color` (str): Hex color code for UI display
- `messages` (list): List of feedback strings — both individual ✅ pass messages and fail messages are included

**Evaluation Logic**:

#### Structural Checks (5 points)
1. Length >= 12 characters
2. Contains uppercase letter
3. Contains lowercase letter
4. Contains digits
5. Contains special characters (punctuation)

#### Veto Checks (2 bonus points)
1. Not in `COMMON_PASSWORDS` list (exact match, case-insensitive)
2. Does not contain any `DICTIONARY_WORDS` (case-insensitive substring check)

**Scoring System**:
- Maximum score: 7 points (5 structural + 2 veto)
- **STRONG**: No veto triggers AND score = 7
- **MODERATE**: No veto triggers AND score = 5–6
- **WEAK**: Veto triggered OR score <= 4

**Special Behaviors**:
- Each passing check stores an individual ✅ success message (not one generic message)
- Veto checks override structural score — common password or dictionary word = automatic WEAK
- Case-insensitive matching for both common passwords and dictionary words
- Returns early with warning if input is empty

---

All password checks and feedback are shown in real time via the Streamlit interface. No raw passwords are ever saved — only hashes are stored in `data/passwords.txt`.

</details>

---

<details>
<summary> 🔑 Password Generator & Hasher </summary>
<br>

Generates cryptographically secure passwords and hashes them with SHA-256 + random salt. Integrated into the Streamlit GUI via `app.py`.

**File**: `src/features/password_generator.py`

**Used by `app.py`**:
```python
from features.password_generator import generate_password, hash_password, save_to_file
```

---

### generate_password(length=12)
**Purpose**: Generate a cryptographically secure random password.

**Parameters**:
- `length` (int, default=12): Desired password length (clamped to 8–32)

**Returns**: String containing the generated password

**Details**:
- Ensures at least one character from each class: uppercase, lowercase, digit, punctuation
- Remaining characters randomly selected from all character classes
- Final password is shuffled for randomness
- Length automatically clamped if below 8 or above 32

---

### hash_password(password)
**Purpose**: Hash a password using SHA-256 with a random salt.

**Parameters**:
- `password` (str): Password to hash

**Returns**: Tuple of `(salt_hex, hash_hex)`
- `salt_hex` (str): 16-byte salt as hex string
- `hash_hex` (str): SHA-256 hash as hex string

**Details**:
- Generates 16-byte random salt using `os.urandom()`
- Prepends salt to password before hashing
- Returns both salt and hash (both are needed for verification)

---

### save_to_file(salt_hex, hash_hex, timestamp, password=None)
**Purpose**: Save a hash entry to file. The raw password is **never** saved.

**Parameters**:
- `salt_hex` (str): Salt in hexadecimal
- `hash_hex` (str): Hash in hexadecimal
- `timestamp` (str): Timestamp string
- `password` (str, optional): NOT SAVED — parameter exists for validation use only

**Returns**: Boolean (True if saved successfully)

**File Format**: `[timestamp] | hash # salt`

**Security**: Raw password is NEVER written to disk. Only hash and salt are stored. *(and it should stay that way — please don't change this!)*

---

Generated passwords are never saved to disk. Only hashes (with salt) are stored in `data/passwords.txt`. All actions are available in the Streamlit interface.

</details>

---

<details>
<summary> 📝 Web Form Validator & Sanitizer </summary>
<br>

Validates and sanitizes web form inputs (Full Name, Email, Username, Message) against XSS, SQL injection, and disposable emails. Integrated into the Streamlit GUI via `app.py`.

**File**: `src/features/webform_validator.py`

**Used by `app.py`**:
```python
from features.webform_validator import validate_and_sanitize_form
```

---

### validate_and_sanitize_form(form_data)
**Purpose**: Main entry point — validates and sanitizes all four form fields in one call.

**Parameters**:
- `form_data` (dict): Keys: `full_name`, `email`, `username`, `message`

**Returns**: Dictionary containing:
- `validation`: Per-field validation results
- `sanitized`: Sanitized values for each field
- `errors`: List of error messages
- `summary`: List of sanitization action descriptions
- `all_valid`: Boolean overall validity
- `has_empty_fields`: Boolean if any required fields are missing

---

### Validation Rules (per field)

**Full Name**:
- Required field (min 1 character after strip)
- Minimum 2 characters
- No digits allowed
- Only letters, spaces, apostrophes, hyphens
- Maximum 1 consecutive space (strictly single-space only)

**Email** (RFC 5321 compliant):
- Required field
- Length: 6–320 characters total; local part max 64 chars
- No spaces allowed; must contain exactly one `@`
- Valid TLD (2–63 chars, letters only); no consecutive dots
- Blocks disposable email domains (yopmail.com, mailinator.com, temp-mail.org, etc.)

**Username**:
- Required field
- Length: 4–16 characters
- Must start with a letter (not a number)
- No spaces; only letters, numbers, underscores
- No consecutive underscores

**Message**:
- Required field; maximum 250 characters
- Blocks SQL keywords: `SELECT`, `DROP`, `INSERT`, `DELETE`, `UPDATE`, `UNION`, etc.
- Blocks XSS patterns: `<script>`, `<iframe>`, `javascript:`, event handlers (`onclick=`, etc.)
- Blocks admin panel references: `admin`, `login`, `wp-admin`, `phpmyadmin`

---

### Sanitization (internal — called inside validate_and_sanitize_form)

Each field has a corresponding `sanitize_*` function called internally:

- `sanitize_full_name(name)`: Removes digits and invalid chars, formats to Title Case
- `sanitize_email(email)`: Removes spaces, normalizes to lowercase
- `sanitize_username(username)`: Removes invalid chars, normalizes to lowercase
- `sanitize_message(message)`: 9-layer sanitization (removes scripts, escapes HTML entities, filters SQL keywords)

---

All validation results and sanitized output are returned in the results dict and displayed in the Streamlit interface. Users only see clean pass/fail messages. ✨abstraction✨

</details>

---

<details>
<summary> 🔍 Network Port Scanner </summary>
<br>

Scans a host for open TCP ports using presets or custom ranges, identifies services, checks vulnerabilities, and visualizes results. Integrated into the Streamlit GUI via `app.py`.

**File**: `src/features/network_port_scanner.py`

**Used by `app.py`**:
```python
from features.network_port_scanner import PORT_PRESETS, COMMON_PORTS_BY_CATEGORY, validate_host, validate_port_range, scan_port_range, get_service_name
```

**References**:
- Common Ports: https://www.stationx.net/common-ports-cheat-sheet/
- Steam Ports: https://help.steampowered.com/en/faqs/view/2EA8-4D75-DA21-31EB
- Valorant Ports: https://support-valorant.riotgames.com/hc/en-us/articles/4402306473619

---

### validate_host(host)
**Purpose**: Validate if the host is reachable/resolvable before scanning.

**Parameters**:
- `host` (str): IP address or hostname to validate

**Returns**: Tuple of `(is_valid, error_message)`

**Details**:
- Uses `socket.gethostbyname()` to resolve hostname
- Returns False with message if host is empty, unreachable, or invalid

---

### validate_port_range(start_str, end_str)
**Purpose**: Validate port range input from the user.

**Parameters**:
- `start_str` (str): Starting port as string
- `end_str` (str): Ending port as string

**Returns**: Tuple of `(is_valid, start_port, end_port, error_message)`

**Validation Rules**:
- Both values must be integers (no letters or symbols)
- Range must be within 1–65535
- Start port must be <= end port
- Maximum range of 10,000 ports per scan *(any more and your computer will cry)*
- Single port (start == end) is allowed

---

### scan_port_range(host, start_port, end_port, timeout=0.5, callback=None, cancel_check=None)
**Purpose**: Scan a range of TCP ports on the specified host.

**Parameters**:
- `host` (str): Target IP address or hostname
- `start_port` (int): Starting port number
- `end_port` (int): Ending port number (inclusive)
- `timeout` (float, default=0.5): Connection timeout per port
- `callback` (function, optional): Called after each port with `(port, is_open)` for real-time UI updates
- `cancel_check` (function, optional): Returns True to stop scanning immediately (used when user switches tabs)

**Returns**: Dictionary with keys:
- `open`: List of open port numbers
- `closed`: List of closed port numbers

---

### get_service_name(port)
**Purpose**: Get the service name for a known port number.

**Parameters**:
- `port` (int): Port number

**Returns**: String (service name or `"Unknown Service"`)

**Details**:
- Looks up port in the `PORT_SERVICE_MAP` dictionary built from `COMMON_PORTS_BY_CATEGORY`

---

### PORT_PRESETS (Dictionary)
**Purpose**: Predefined port categories for quick selection in the UI dropdown.

| Category | Ports | Description |
|---|---|---|
| Web Services | 80, 443 | HTTP and HTTPS |
| Mail Services | 25, 110, 143 | SMTP, POP3, IMAP |
| Remote Access & Management | 22, 23, 3389 | SSH, Telnet, RDP |
| Directory / Authentication | 88, 389, 464, 636 | Kerberos, LDAP |
| File Transfer & Sharing | 20, 21, 69, 445 | FTP, TFTP, SMB |
| Network Core | 53, 67, 68, 123 | DNS, DHCP, NTP |
| Network Management & Monitoring | 161 | SNMP |
| Communication, VoIP, and Chat | 194, 1720, 5060, 5061 | IRC, H.323, SIP |
| Legacy and Testing | 7, 23 | Echo, Telnet |
| Steam | 80, 443, 27000–27100 | Steam platform |
| Valorant | 80, 443, 7000–8000 | Valorant game |

*Yes, we added gaming ports. Priorities~*

### COMMON_PORTS_BY_CATEGORY (Dictionary)
**Purpose**: Full port-to-service mapping used to build `PORT_SERVICE_MAP` and populate the common ports reference table in the UI.

---

### Port Vulnerability Check
**File**: `src/utils/port_vulnerability_db.py`

**Used by `app.py`**:
```python
from utils.port_vulnerability_db import render_vulnerability_section, get_port_data, get_overall_risk, RISK_ORDER, RISK_COLORS, RISK_BADGE
```

Displays risk assessments and live CVE data for each open port found during a scan. Rendered automatically after every completed scan.

**render_vulnerability_section(open_ports)**
**Purpose**: Main renderer — displays the full vulnerability check panel for all open ports.

**Parameters**:
- `open_ports` (list): List of open port numbers from the scan

**Details**:
- Fetches IANA service name and description for each port
- Queries the NVD API (via `nvdlib`) for live CVEs using the service name
- Derives risk level from the highest CVSS score returned
- Displays an overall risk banner, a summary table, and per-port detail cards
- Clicking **↗ View** on a CVE redirects to the full NIST NVD page
- Clicking **View port XX on ScaniteX ↗** redirects to the Port Encyclopedia page for that port

**get_port_data(port)**
**Purpose**: Build a complete data dict for one port — IANA info + NVD CVEs + risk level.

**Returns**: Dict with keys: `port`, `service`, `description`, `risk`, `cvss_max`, `cves`, `scanitex`

**get_overall_risk(port_data_list)**
**Purpose**: Returns the highest risk level across all scanned ports.

**Risk Levels**: CRITICAL (CVSS >= 9.0) → HIGH (>= 7.0) → MEDIUM (>= 4.0) → LOW (< 4.0)

**Constants used by `app.py`**:
- `RISK_ORDER`: List of risk levels in descending severity order
- `RISK_COLORS`: Dict mapping risk level to hex color
- `RISK_BADGE`: Display label per risk level (e.g., `"🔴 CRITICAL"`)

---

### Scan Analysis (Data Visualization)

Interactive Plotly charts rendered inside a **Scan Analysis** expander after every completed scan.

**KPI Stat Cards**: Ports Scanned, Open Ports, Closed Ports, Scan Duration

**Charts**:
- **Open vs Closed Ports** — donut chart
- **Open Ports by Service Category** — horizontal bar chart
- **Discovered Open Ports — Number Line** — spike chart with service labels per port

---

### Network Path — Traceroute

Scapy-based traceroute rendered in a **Network Path** expander after scanning. Requires admin/sudo privileges (same as Traffic Analyzer).

**run_scapy_traceroute(target, min_ttl=1, max_ttl=30, timeout=3)**
**Purpose**: Run a traceroute to the target using Scapy with auto-detected gateway MAC.

**Returns**: List of hop dicts with keys: `ttl`, `ip`, `hostname`, `rtt_ms`, `icmp_type`, `is_target`, `responded`

**build_traceroute_graph(hops, target_host)**
**Purpose**: Render the hop path as an interactive Plotly network graph.

**Node colors**: Cyan = origin, Blue = intermediate hop, Green = target, Grey = no response (`* * *`)

**KPI Stat Cards**: Total Hops, Target Reached, No-Response Hops, Final RTT

---

Scan results can be exported as CSV. All actions are available in the Streamlit interface.

</details>

---

<details>
<summary> 📡 Network Traffic Analyzer </summary>
<br>

Captures and analyzes live network packets using Scapy. Supports BPF filtering by protocol, port, host, and IP. Displays results in real time in the Streamlit GUI via `app.py`.

**File**: `src/features/network_traffic_analyzer.py`

**Used by `app.py`**:
```python
from features.network_traffic_analyzer import get_scapy_status, validate_filter, start_packet_capture
```

**Requirements**:
- Scapy library (`pip install scapy`)
- Admin/root privileges (sudo on macOS/Linux, Run as Administrator on Windows)

*BPF = Berkeley Packet Filter — a fancy way to say "filter what packets you want to see." Named after UC Berkeley where it was invented!*

*If it says "permission denied" → you forgot sudo! Don't worry, we've all been there~*

---

### get_scapy_status()
**Purpose**: Check Scapy installation and privilege status for display in the UI before allowing capture to start.

**Parameters**: None

**Returns**: Tuple of `(scapy_installed, has_privileges, status_message)`

**Status Messages**:
- `"Scapy not installed. Install with: pip install scapy"`
- `"Administrator privileges required (Run as Administrator)"`
- `"Root privileges required (use sudo)"`
- `"Ready to capture packets"`

---

### validate_filter(proto="", port="", host="", src_ip="", dst_ip="")
**Purpose**: Build and validate a BPF filter string from the GUI input fields.

**Parameters**:
- `proto` (str): Protocol filter (`tcp`, `udp`, `icmp`, `ip`, `arp`, `ip6`)
- `port` (str): Port number filter
- `host` (str): General host/IP filter
- `src_ip` (str): Source IP filter
- `dst_ip` (str): Destination IP filter

**Returns**: Tuple of `(is_valid, filter_or_error)`
- `is_valid` (bool): True if filter is valid
- `filter_or_error` (str): BPF filter string if valid, error message if invalid

**Details**:
- Validates protocol against allowed list
- Validates port is numeric
- Resolves hostnames using `socket.gethostbyname()`
- Combines multiple filters with `"and"` operator
- Returns empty string if no filters (captures all traffic)

**Example Filters**:
- `tcp port 80` — HTTP traffic only
- `host 192.168.1.1` — traffic to/from a specific IP
- `tcp and src host 10.0.0.5` — TCP from a specific source

*Leave filter empty to capture EVERYTHING (but be ready for a LOT of packets!)*

---

### start_packet_capture(filter_string="", packet_callback=None, stop_callback=None, count=0)
**Purpose**: Start capturing packets with the specified BPF filter.

**Parameters**:
- `filter_string` (str): BPF filter string (empty = capture all)
- `packet_callback` (function): Called for each captured packet with a formatted packet info dict
- `stop_callback` (function): Returns True to stop capture
- `count` (int): Number of packets to capture (0 = unlimited)

**Returns**: List of raw Scapy packet objects (used by `app.py` for PCAP export via `wrpcap`)

**Raises**:
- `ImportError`: If Scapy is not installed
- `PermissionError`: If not running with sufficient privileges
- `ValueError`: If filter is invalid

**Details**:
- Checks Scapy availability and privileges before starting
- Stores raw packets for PCAP export
- Uses Scapy's `sniff()` with `stop_filter`
- Provides platform-specific error messages for privilege issues

---

### Traffic Analysis (Data Visualization)

Interactive Plotly charts rendered inside a **Traffic Analysis** expander after pausing or stopping capture.

**KPI Stat Cards**: Total Packets, Unique Sources, Unique Destinations, Top Protocol
- Unique Sources/Destinations correctly exclude `N/A` entries from Unknown/ARP packets

**Charts**:
- **Protocol Distribution** — donut chart (TCP, UDP, ICMP, Other)
- **Top 8 Source IPs (Talkers)** — horizontal bar chart
- **Top 10 Destination Ports** — treemap
- **Packet Volume Over Time** — line/area chart (per second)
- **Source Device Vendor Breakdown** — donut chart (shown when vendor data is available)

---

Requires admin/sudo privileges for packet capture. Captured data can be exported as CSV or PCAP (Wireshark-compatible). All actions are available in the Streamlit interface.

</details>

---

<details>
<summary> 🔗 URL Expander </summary>
<br>

Expands shortened URLs to reveal their true destination by following HTTP redirects. Integrated into the Streamlit GUI via `app.py`.

**File**: `src/features/url_expander.py`

**Used by `app.py`**:
```python
from features.url_expander import expand_url
```

---

### expand_url(short_url)
**Purpose**: Follow all redirects from a shortened URL and return the final destination.

**Parameters**:
- `short_url` (str): The shortened or redirecting URL to expand

**Returns**: String — the final expanded URL, or an error message starting with `"Error:"` if the request fails

**Details**:
- Sends an HTTP HEAD request (faster — no content download)
- Follows all redirects automatically (`allow_redirects=True`)
- Timeout: 10 seconds
- Returns the resolved `response.url` as the final destination
- Handles `RequestException` and returns a user-friendly error string

**GUI**:
- Streamlit tab with a URL input field
- **Expand URL** button
- Displays the final destination URL or an error message
- Input validation and error feedback

**Testing**:
- Verified with TinyURL, Bitly, and invalid/unreachable links
- All test cases passed ✓

*Requires internet access. No URLs are visited in a browser — only HEAD requests are sent.*

</details>

---

<details>
<summary> 🛑 URL Scam Scanner </summary>
<br>

Analyzes URLs for phishing and scam indicators using 8 offline heuristic rules. No internet connection required. Integrated into the Streamlit GUI via `app.py`.

**File**: `src/features/url_scam_scanner.py`

**Used by `app.py`**:
```python
from features.url_scam_scanner import scan_url
```

**Rule Sources**:
- University of Denver IT — "5 URL Warning Signs to Watch For"
- TCM Security — "How To Identify URL Phishing Techniques"
- Medium — "Threat Hunting - Suspicious TLDs"

---

### scan_url(url)
**Purpose**: Run all 8 heuristic rules against a URL and return a verdict with risk flags.

**Parameters**:
- `url` (str): The URL to scan (scheme optional — `https://` is prepended if missing)

**Returns**: Dictionary with keys:
- `url` (str): Normalized URL
- `verdict` (str): `"LIKELY MALICIOUS"`, `"SUSPICIOUS"`, or `"SAFE"`
- `score` (int): Cumulative risk score
- `flags` (list): List of triggered rule dicts, each with `flag`, `severity`, `detail`
- `domain` (str): Registered domain
- `tld` (str): Top-level domain
- `suggest_expander` (bool): True if a URL shortener was detected
- `expander_message` (str or None): Ready-made message displayed when prompting the user to use the URL Expander

**Verdict Thresholds**:
- Score >= 5 → `LIKELY MALICIOUS`
- Score >= 2 → `SUSPICIOUS`
- Score < 2 → `SAFE`

---

### Heuristic Rules (8 total)

| # | Rule | Severity | Description |
|---|---|---|---|
| 1 | IP as domain | HIGH | Raw IP address used instead of a domain name |
| 2 | Brand in subdomain | HIGH | Known brand appears in subdomain of a different registered domain |
| 3 | Typosquatting | HIGH | Domain is 1 character away from a known brand (Levenshtein distance) |
| 4 | HTTP (no HTTPS) | MEDIUM | Connection is unencrypted |
| 5 | Excessive hyphens | MEDIUM | 3 or more hyphens in the domain name |
| 6 | URL shortener | MEDIUM | Domain is a known shortening service (bit.ly, tinyurl.com, etc.) |
| 7 | Open redirect | MEDIUM | Query string contains a redirect parameter (`url=`, `redirect=`, etc.) |
| 8 | Suspicious TLD | MEDIUM | TLD has a disproportionately high abuse rate (`.xyz`, `.tk`, `.top`, etc.) |

**Severity Scores**: HIGH = 3 pts, MEDIUM = 2 pts, LOW = 1 pt

---

**GUI**:
- URL input field with **Scan URL** button
- Color-coded verdict banner: 🚨 Likely Malicious / ⚠️ Suspicious / ✅ Safe
- Domain and TLD breakdown
- Per-flag detail cards (color-coded by severity: red / orange / yellow)
- When a URL shortener is detected, prompts the user to use the URL Expander tool first

**Testing**:
- Verified with safe, suspicious, and shortened URLs
- All test cases passed ✓

*Works fully offline. No data is sent externally. Detection is based on structural rules and pattern matching only.*

</details>

---

<details>
<summary> 🎨 Global Variables & Constants </summary>
<br>

### DICTIONARY_WORDS
*(from `src/utils/dictionary.py`, loaded at startup)*

Combined list from `load_dictionary()` + `load_nltk_words()`, deduplicated and sorted.

**Usage**: Used internally by `evaluate_password_strength()` to detect dictionary words inside passwords.

---

### COMMON_PASSWORDS
*(in `src/features/password_strength.py`)*

Hardcoded set of very common passwords that immediately mark a password as WEAK.

**Examples**: `"password"`, `"123456"`, `"qwerty"`, `"admin"`, `"letmein"`

*Seriously, if you're using any of these... please try not to...*

---

### Color Constants
*(in `src/features/password_strength.py`)*

| Constant | Value | Usage |
|---|---|---|
| `COLOR_WEAK` | `#ef4444` | Red — weak passwords |
| `COLOR_MOD` | `#f59e0b` | Orange — moderate passwords |
| `COLOR_STRONG` | `#22c55e` | Green — strong passwords |

---

### SQL_KEYWORDS
*(in `src/features/webform_validator.py`)*

List of SQL keywords used to detect injection attempts in the Message field: `SELECT`, `DROP`, `INSERT`, `DELETE`, `UPDATE`, `UNION`, etc.

---

### DANGEROUS_PATTERNS
*(in `src/features/webform_validator.py`)*

Regex patterns used to detect XSS and malicious code: `<script>`, `javascript:`, `onclick=`, etc.

---

### DISPOSABLE_DOMAINS
*(in `src/features/webform_validator.py`)*

Blocked temporary email services:
- yopmail.com
- mailinator.com
- temp-mail.org
- guerrillamail.com
- 10minutemail.com
- trashmail.com
- throwaway.email

---

### RISK_ORDER / RISK_COLORS / RISK_BADGE
*(in `src/utils/port_vulnerability_db.py`, imported directly by `app.py`)*

Used by `app.py` to render risk labels and colors in the Port Vulnerability Check UI.

- `RISK_ORDER`: `["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]`
- `RISK_COLORS`: Hex color per risk level
- `RISK_BADGE`: Display label per risk level (e.g., `"🔴 CRITICAL"`)

</details>

---

<details>
<summary> 🖥️ GUI Features </summary>
<br>

### Real-Time Input (Password Strength)
Uses `st_keyup` from `streamlit-keyup` for character-by-character feedback without needing to press Enter or click a button.

---

### Inline Validation Feedback (Web Form Validator)
- ✓ Valid (green) — field passes all checks
- ✗ Error (red) — lists ALL violations per field, not just the first one

Users only see clean pass/fail messages — sanitization details are not shown. ✨abstraction✨

---

### Tool Locking
- Port Scanner locks out Traffic Analyzer while a scan is active (and vice versa)
- Prevents conflicts from simultaneous network operations
- Warning banner shown when the other tool is in use
- Implemented via `st.session_state` flags (`scan_running`, `capturing`)

---

### Auto-Refresh
`app.py` calls `st.rerun()` on a short sleep loop while a scan or capture is active, keeping the UI live without manual interaction.

</details>

---

<details>
<summary> 📜 Version History </summary>
<br>

| Version | Date | Changes |
|---|---|---|
| **MS1 (Draft)** | Jan 26, 2026 | Password Strength Analyzer, Password Generator, Web Form Validator |
| **MS1 (Final)** | Jan 27, 2026 | Bug fixes, security logging system |
| **MS2 (GUI)** | Feb 1, 2026 | Migrated from Tkinter to Streamlit |
| **MS2** | Feb 24, 2026 | Added Network Port Scanner, Traffic Analyzer |
| **MS2 (Revisions)** | Mar 2, 2026 | PCAP export, no-limit scanning, pause/resume, BPF filters |
| **MS2 (Data Viz)** | Mar 8, 2026 | Plotly visualizations, traceroute graph, cross-platform gateway detection |
| **TA (Draft)** | Mar 23, 2026 | URL Expander, URL Scam Scanner, Port Vulnerability DB |
| **TA (Updates)** | Mar 26, 2026 | Merged ta-draft to main, bug fixes, Password Strength individual pass messages |
| **TA (Final)** | Mar 28, 2026 | Updated Documentation.md and README.md |

---

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
- Implemented security logging system (used by Tkinter GUI)

</details>

<details>
<summary> MS2 Details </summary>

**Network Features (Feb 24, 2026):**
- Network Port Scanner with TCP scanning, presets, real-time results, and CSV export
- Network Traffic Analyzer with Scapy — live packet capture, BPF filters

**Revisions (Mar 2, 2026):**
- PCAP export functionality (Wireshark-compatible)
- No-limit packet capture option (count = 0)
- Pause/Resume capture controls
- BPF filter support for protocol, port, host, source IP, destination IP filtering

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
- GUI: Streamlit tab with input, Expand button, result display, and error feedback
- Testing: Verified with TinyURL, Bitly, and invalid links — all passed

*URL Scam Scanner:*
- Backend: 8 offline heuristic rules (IP as domain, typosquatting, brand impersonation, suspicious TLDs, URL shorteners, open redirects, excessive hyphens, no HTTPS)
- GUI: Color-coded verdict, per-flag detail cards, URL shortener cross-tool prompt
- Testing: Verified with safe, scam, and shortened URLs — all passed

*Port Scanner — Port Vulnerability DB:*
- Backend: `port_vulnerability_db.py` with IANA lookup, NVD CVE fetching (`nvdlib`), CVSS-based risk scoring
- GUI: `render_vulnerability_section()` called automatically after each scan
- Clicking ↗ View on a CVE → NIST NVD page
- Clicking View port XX on ScaniteX ↗ → Port Encyclopedia for that port

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

*made with 💻 ♡ and probably too much coffee~ ☕*

*BSIT-S31101 | MO-IT139 Security Script Programming | 2026*