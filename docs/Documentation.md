# 📚 Technical Documentation
**PASSECURIST - Security Script Programming**

> *"Welcome~!*

---

<details>
<summary> 📂 Project Structure </summary>
<br>

```
MO-IT139_Security_Script_Programming/
│
├── app.py                              # Streamlit main entry point with tabbed interface
├── README.md                           # Project documentation
│
├── data/
│   ├── dictionary.txt                  # Local word list for password strength checking (optional)
│   ├── passwords.txt                   # Hash storage (NO raw passwords saved)
│   └── security_log.txt                # Attack/sanitization event logs
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

---

<details>
<summary> 🔐 Password Strength Analyzer </summary>
<br>

### load_dictionary()
**Purpose**: Loads a local dictionary file (dictionary.txt) into a Python list used to detect words inside passwords.

**Parameters**: None

**Returns**: List of words (lowercase) with length >= 4

**Details**: 
- Reads dictionary.txt from the data folder
- Filters words to keep only those with 4+ characters
- Prints debug messages and returns a small fallback list when dictionary.txt is missing
- Fallback words: ["apple", "computer", "dragon", "monkey", "secret"]
- *Fun fact: these fallback words are surprisingly common in real passwords... please don't use them!*

---

### load_nltk_words(min_len=4, max_len=None)
**Purpose**: Loads words from the NLTK corpus (if installed) and returns them filtered by length.

**Parameters**:
- `min_len` (int, default=4): Minimum word length
- `max_len` (int or None): Maximum word length (None = no limit)

**Returns**: List of corpus words in lowercase meeting length rules

**Notes**:
- Returns empty list [] if NLTK is not installed or corpus is missing
- Does not automatically download corpus
- Current implementation: `nltk` is imported at the top (unguarded)
  - **Warning**: Code will crash if nltk is not installed *(oops~)*
  - Future improvement: Guard the import for better error handling
  - *Note to self: NLTK is optional but makes the dictionary WAY bigger*

---

### evaluate_password_strength(password)
**Purpose**: Main password assessment function that tests password strength and provides detailed feedback.

**Parameters**:
- `password` (str): The password to evaluate

**Returns**: Tuple of (rating, color, messages)
- `rating` (str): "WEAK", "MODERATE", or "STRONG"
- `color` (str): Hex color code for UI display
- `messages` (list): List of feedback strings

**Evaluation Logic**:

#### Structural Checks (5 points)
1. Length >= 12 characters
2. Contains uppercase letter
3. Contains lowercase letter
4. Contains digits
5. Contains special characters (punctuation)

#### Veto Checks (2 bonus points)
1. Not in COMMON_PASSWORDS list (exact match, case-insensitive)
2. Does not contain any DICTIONARY_WORDS (case-insensitive substring check)

**Scoring System**:
- Maximum score: 7 points (5 structural + 2 veto bonuses)
- **STRONG**: No veto triggers AND score = 7
- **MODERATE**: No veto triggers AND score = 5-6
- **WEAK**: Veto triggered OR score <= 4

**Special Behaviors**:
- Veto checks override structural score (common password or dictionary word = automatic WEAK)
- Detected dictionary words are printed to terminal for debugging
- Case-insensitive matching for both common passwords and dictionary words
- Returns early with warning if input is empty

---

### show_custom_warning(title, message)
**Purpose**: Display a custom-themed modal warning window.

**Parameters**:
- `title` (str): Window title
- `message` (str): Warning message to display

**Returns**: None (displays popup)

**Details**:
- Creates a blocking popup using the app's dark blue theme
- Matches main application styling
- Called when user submits empty input in evaluate_password_strength()

</details>

---

<details>
<summary> 🔑 Password Generator & Hasher </summary>
<br>

### generate_password(length=12)
**Purpose**: Generate a cryptographically secure password.

**Parameters**:
- `length` (int, default=12): Desired password length (clamped to 8-16)

**Returns**: String containing generated password

**Details**:
- Ensures at least one character from each class: uppercase, lowercase, digit, punctuation
- Remaining characters randomly selected from all classes
- Final password is shuffled for randomness
- Length automatically adjusted if below 8 or above 16

---

### hash_password(password)
**Purpose**: Hash a password using SHA-256 with random salt.

**Parameters**:
- `password` (str): Password to hash

**Returns**: Tuple of (salt_hex, hash_hex)
- `salt_hex` (str): 16-byte salt as hex string
- `hash_hex` (str): SHA-256 hash as hex string

**Details**:
- Generates 16-byte random salt using os.urandom()
- Prepends salt to password before hashing
- Returns both salt and hash (both needed for verification)

---

### save_to_file(salt_hex, hash_hex, timestamp, password=None)
**Purpose**: Save hash entry to file (password parameter is NOT saved).

**Parameters**:
- `salt_hex` (str): Salt in hexadecimal
- `hash_hex` (str): Hash in hexadecimal
- `timestamp` (str): Timestamp string
- `password` (str, optional): NOT SAVED - only used for validation

**Returns**: Boolean (True if saved successfully)

**File Format**: `[timestamp] | hash # salt`

**Security**: Raw password is NEVER written to disk, only hash and salt are stored. *(and it should stay that way — please don't change this!)*

</details>

---

<details>
<summary> 📝 Web Form Validator & Sanitizer </summary>
<br>

### validate_full_name(name)
**Purpose**: Validate full name field with security checks.

**Returns**: Tuple of (valid, message, details)

**Validation Rules**:
- Required field (min 1 character after strip)
- Minimum 2 characters
- No digits allowed
- Only letters, spaces, apostrophes, hyphens
- Maximum 2 consecutive spaces

---

### validate_email(email)
**Purpose**: Validate email address with RFC 5321 compliance and security checks.

**Returns**: Tuple of (valid, message, details)

**Validation Rules**:
- Required field
- Length: 6-320 characters
- No spaces allowed
- Must contain exactly one '@' symbol
- Local part (before @): max 64 chars, alphanumeric start/end, allows ._+-
- Domain part (after @): must have dot, valid TLD (2-63 chars, letters only)
- Blocks disposable email domains (yopmail.com, mailinator.com, temp-mail.org, etc.)
- No consecutive dots in local or domain parts

**Reference**: https://whoapi.com/blog/understanding-valid-email-address-formats-a-short-guide/

---

### validate_username(username)
**Purpose**: Validate username with security and format checks.

**Returns**: Tuple of (valid, message, details)

**Validation Rules**:
- Required field
- Length: 4-16 characters
- Must start with letter (not number)
- No spaces allowed
- Only letters, numbers, underscores
- No consecutive underscores

---

### validate_message(message)
**Purpose**: Validate message with XSS and SQL injection detection.

**Returns**: Tuple of (valid, message, details, threats)

**Validation Rules**:
- Required field
- Maximum 250 characters
- Blocks SQL keywords: SELECT, DROP, INSERT, DELETE, UPDATE, UNION, etc.
- Blocks XSS patterns: `<script>`, `<iframe>`, `javascript:`, event handlers
- Blocks admin panel references: admin, login, wp-admin, phpmyadmin

---

### sanitize_* functions
**Purpose**: Clean and normalize input for safe database storage.

**Functions**:
- `sanitize_full_name(name)`: Removes digits and invalid chars, formats to Title Case
- `sanitize_email(email)`: Removes spaces, normalizes to lowercase
- `sanitize_username(username)`: Removes invalid chars, normalizes to lowercase
- `sanitize_message(message)`: 9-layer sanitization (removes scripts, HTML entities, SQL keywords)

**Returns**: Tuple of (sanitized_value, was_sanitized)

---

### validate_and_sanitize_form(form_data)
**Purpose**: Main validation function for all form fields.

**Parameters**:
- `form_data` (dict): Dictionary with keys: full_name, email, username, message

**Returns**: Dictionary containing:
- `validation`: Per-field validation results
- `sanitized`: Sanitized values for each field
- `errors`: List of error messages
- `summary`: List of sanitization actions
- `all_valid`: Boolean overall validity
- `has_empty_fields`: Boolean if required fields missing

</details>

---

<details>
<summary> 🔍 Network Port Scanner </summary>
<br>

### Overview
Scans TCP ports on a target host to identify open/closed ports. Includes preset categories for common services (Web, Mail, Gaming, etc.).

<!--*Like knocking on doors to see which ones are open~ except the doors are network ports and we're checking if services are running behind them. So the doors are port als, and if you knock and they're open you can get sucked right in to another dimension, ha! Kidding, you can choose to cross or not. Because the portal is open or you can throw in pebbles in the portal and maybe you'll find that this portal is the backdoor to the president's suite, or a suburban toilet*-->


**File**: `src/features/network_port_scanner.py`

**References**:
- Common Ports: https://www.stationx.net/common-ports-cheat-sheet/
- Steam Ports: https://help.steampowered.com/en/faqs/view/2EA8-4D75-DA21-31EB
- Valorant Ports: https://support-valorant.riotgames.com/hc/en-us/articles/4402306473619

---

### scan_port(host, port, timeout=0.5)
**Purpose**: Scan a single TCP port on the specified host.

**Parameters**:
- `host` (str): Target IP address or hostname
- `port` (int): Port number to scan
- `timeout` (float, default=0.5): Connection timeout in seconds

**Returns**: Boolean (True if port is open, False if closed)

**Details**:
- Creates a TCP socket (AF_INET, SOCK_STREAM)
- Uses connect_ex() which returns 0 if connection succeeds
- Closes socket after each attempt
- Returns False on any socket error

---

### scan_port_range(host, start_port, end_port, timeout=0.5, callback=None, cancel_check=None)
**Purpose**: Scan a range of ports on the specified host.

**Parameters**:
- `host` (str): Target IP address or hostname
- `start_port` (int): Starting port number
- `end_port` (int): Ending port number (inclusive)
- `timeout` (float, default=0.5): Connection timeout per port
- `callback` (function, optional): Called after each port scan for real-time UI updates
- `cancel_check` (function, optional): Called before each port — returns True to stop scan immediately

**Returns**: Dictionary with keys:
- `open`: List of open port numbers
- `closed`: List of closed port numbers

**Details**:
- Iterates through port range sequentially
- Calls callback(port, is_open) for each port scanned
- Checks cancel_check() before each port; exits loop immediately if it returns True
- Useful for real-time progress updates and safe mid-scan cancellation in GUI

---

### validate_host(host)
**Purpose**: Validate if the host is reachable/resolvable.

**Parameters**:
- `host` (str): IP address or hostname to validate

**Returns**: Tuple of (is_valid, error_message)
- `is_valid` (bool): True if host is valid
- `error_message` (str or None): Error description if invalid

**Details**:
- Uses socket.gethostbyname() to resolve hostname
- Returns False with message if host is empty, unreachable, or invalid

---

### validate_port_range(start_str, end_str)
**Purpose**: Validate port range input from user.

**Parameters**:
- `start_str` (str): Starting port as string
- `end_str` (str): Ending port as string

**Returns**: Tuple of (is_valid, start_port, end_port, error_message)

**Validation Rules**:
- Both values must be integers (no letters or symbols)
- Range must be within 1-65535
- Start port must be <= end port
- Maximum range of 10,000 ports for performance *(any more and your computer will cry)*
- Single port (start == end) is allowed

---

### get_service_name(port)
**Purpose**: Get the service name for a known port number.

**Parameters**:
- `port` (int): Port number

**Returns**: String (service name or "Unknown Service")

**Details**:
- Looks up port in PORT_SERVICE_MAP dictionary
- Common services: HTTP(80), HTTPS(443), SSH(22), FTP(21), DNS(53), etc.

---

### PORT_PRESETS (Dictionary)
**Purpose**: Predefined port categories for quick selection in UI.

**Categories**:
| Category | Ports | Description |
|----------|-------|-------------|
| Web Services | 80, 443 | HTTP and HTTPS |
| Mail Services | 25, 110, 143 | SMTP, POP3, IMAP |
| Remote Access & Management | 22, 23, 3389 | SSH, Telnet, RDP |
| Directory / Authentication | 88, 389, 464, 636 | Kerberos, LDAP, LDAPS |
| File Transfer & Sharing | 20, 21, 69, 445 | FTP, TFTP, SMB |
| Network Core | 53, 67, 68, 123 | DNS, DHCP, NTP |
| Network Management & Monitoring | 161 | SNMP |
| Communication, VoIP, and Chat | 194, 1720, 5060, 5061 | IRC, H.323, SIP |
| Legacy and Testing | 7, 23 | Echo, Telnet |
| Steam | 80, 443, 27000-27100 | Steam platform |
| Valorant | 80, 443, 7000-8000 | Valorant game |

*Yes, we added gaming ports. Priorities~ *

</details>

---

<details>
<summary> 📡 Network Traffic Analyzer </summary>
<br>

### Overview
Captures and analyzes network packets using Scapy. Requires administrator/root privileges. Supports BPF (Berkeley Packet Filter) for filtering traffic. Captured packets can be exported as CSV or PCAP.

*BPF = Berkeley Packet Filter, w/c is basically a fancy way to say "filter what packets you want to see." Named after UC Berkeley where it was invented!*

**File**: `src/features/network_traffic_analyzer.py`

**Requirements**:
- Scapy library (`pip install scapy`)
- Admin/root privileges (sudo on macOS/Linux, Run as Administrator on Windows)

*If it says "permission denied" > you forgot sudo! Don't worry, we've all been there~*

---

### check_privileges()
**Purpose**: Check if the script is running with administrator/root privileges.

**Parameters**: None

**Returns**: Boolean (True if has privileges)

**Details**:
- Windows: Uses ctypes.windll.shell32.IsUserAnAdmin()
- Linux/Mac: Uses os.geteuid() == 0

---

### format_packet_info(packet)
**Purpose**: Format packet details for display in the UI.

**Parameters**:
- `packet`: Scapy packet object

**Returns**: Dictionary with keys:
- `timestamp`: Formatted timestamp (YYYY-MM-DD HH:MM:SS.mmm)
- `protocol`: TCP, UDP, ICMP, or Other
- `src_mac`: Source MAC address
- `dst_mac`: Destination MAC address
- `src_ip`: Source IP address
- `dst_ip`: Destination IP address
- `src_port`: Source port (TCP/UDP only)
- `dst_port`: Destination port (TCP/UDP only)
- `summary`: Brief packet description

**Details**:
- Extracts Ethernet, IP, TCP, UDP, ICMP layers
- Handles missing layers gracefully (shows "N/A")
- Catches parsing errors and includes in summary

---

### validate_filter(proto="", port="", host="", src_ip="", dst_ip="")
**Purpose**: Build and validate a BPF (Berkeley Packet Filter) string from GUI fields.

**Parameters**:
- `proto` (str): Protocol filter (tcp, udp, icmp, ip, arp, ip6)
- `port` (str): Port number filter
- `host` (str): General host/IP filter
- `src_ip` (str): Source IP filter
- `dst_ip` (str): Destination IP filter

**Returns**: Tuple of (is_valid, filter_or_error)
- `is_valid` (bool): True if filter is valid
- `filter_or_error` (str): BPF filter string if valid, error message if invalid

**Details**:
- Validates protocol against allowed list
- Validates port is numeric
- Resolves hostnames using socket.gethostbyname()
- Combines filters with "and" operator
- Returns empty string if no filters (captures all traffic)

**Example Filters**:
- `tcp port 80` - HTTP traffic only
- `host 192.168.1.1` - Traffic to/from specific IP
- `tcp and src host 10.0.0.5` - TCP from specific source
- `tcp and dst host 8.8.8.8` - TCP destined for specific IP

*Leave filter empty to capture EVERYTHING (but be ready for a LOT of packets!)*

---

### start_packet_capture(filter_string="", packet_callback=None, stop_callback=None, count=0)
**Purpose**: Start capturing packets with the specified filter.

**Parameters**:
- `filter_string` (str): BPF filter string (empty = capture all)
- `packet_callback` (function): Called for each captured packet with formatted packet info dict
- `stop_callback` (function): Returns True to stop capture
- `count` (int): Number of packets to capture per batch (0 = unlimited)

**Returns**: List of raw Scapy packet objects (used for PCAP export)

**Raises**:
- `ImportError`: If Scapy is not installed
- `PermissionError`: If not running with sufficient privileges
- `ValueError`: If filter is invalid

**Details**:
- Checks Scapy availability and privileges before starting
- Stores raw packets in a local list alongside formatted display data
- Returns raw packet list so the caller (app.py) can accumulate them across batches for PCAP export
- Uses Scapy's sniff() with stop_filter to support mid-capture stops
- In app.py, capture runs in batches of 5 packets per Streamlit rerun cycle, allowing pause/resume without blocking the UI thread
- Provides platform-specific error messages for privilege issues

**Batch Capture Behavior (app.py)**:
- Each Streamlit rerun calls start_packet_capture() with count=5 (or remaining count if packet limit is set)
- Raw packets are accumulated in st.session_state.raw_packets across reruns
- Pause stops the rerun loop; Resume restarts it from where it left off
- A ping timestamp (st.session_state._last_capture_ping) is updated each batch; if 30 seconds pass without a ping, capture is automatically stopped as a safety timeout

---

### get_scapy_status()
**Purpose**: Get Scapy installation and privilege status for UI display.

**Parameters**: None

**Returns**: Tuple of (scapy_installed, has_privileges, status_message)

**Status Messages**:
- "Scapy not installed. Install with: pip install scapy"
- "Administrator privileges required (Run as Administrator)"
- "Root privileges required (use sudo)"
- "Ready to capture packets"

</details>

---

<details>
<summary> 📋 Security Logger </summary>
<br>

### log_threat(field_name, threat_type, original_value, sanitized_value, detected_patterns)
**Purpose**: Log security threats (XSS, SQL injection, etc.) to file.

**Parameters**:
- `field_name` (str): Name of the field (e.g., "Message", "Email")
- `threat_type` (str): Type of threat (e.g., "XSS ATTEMPT", "SQL INJECTION")
- `original_value` (str): Original user input
- `sanitized_value` (str): Cleaned/sanitized value
- `detected_patterns` (list): List of detected malicious patterns

**Returns**: Boolean (True if logged successfully)

**File Location**: `data/security_log.txt`

---

### log_sanitization(field_name, original_value, sanitized_value, reason)
**Purpose**: Log field sanitization actions (character removal, formatting, etc.).

**Parameters**:
- `field_name` (str): Name of the field
- `original_value` (str): Original user input
- `sanitized_value` (str): Cleaned value
- `reason` (str): Description of what was sanitized

**Returns**: Boolean (True if logged successfully)

---

### log_validation_summary(form_data, results)
**Purpose**: Log complete validation summary for a form submission.

**Parameters**:
- `form_data` (dict): Original form data dictionary
- `results` (dict): Validation results from validate_and_sanitize_form()

**Returns**: Boolean (True if logged successfully)

---

### log_attack_attempt(field_name, attack_type, original_value)
**Purpose**: Log serious attack attempts (SQL injection, XSS, disposable emails, etc.).

**Parameters**:
- `field_name` (str): Name of the field
- `attack_type` (str): Type of attack detected
- `original_value` (str): Malicious input attempted

**Returns**: Boolean (True if logged successfully)

---

### Log File Format Examples

**Attack Attempts:**
```
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
[2026-01-27 18:30:45] !!! ATTACK ATTEMPT DETECTED !!! 
  Field: Message
  Attack Type: SQL INJECTION ATTEMPT
  Malicious Input: SELECT * FROM users; DROP TABLE users;
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

**Validation Summary:**
```
**********************************************************************
[2026-01-27 18:32:00] FORM VALIDATION SUMMARY
**********************************************************************
  ✓ Full Name: Valid
  ✓ Email: Valid (sanitized)
  ✗ Username: Invalid - Username must be at least 4 characters long
  ✓ Message: Valid

  Overall Status: FAILED
**********************************************************************
```

</details>

---

<details>
<summary> 🎨 Global Variables & Constants </summary>
<br>

### DICTIONARY_WORDS
Combined list from `load_dictionary()` + `load_nltk_words()`, deduplicated and sorted.

**Usage**: Used to find dictionary words inside passwords

---

### COMMON_PASSWORDS
Short hardcoded list of very common passwords that immediately mark a password as weak.

**Examples**: "password", "123456", "qwerty", "admin", "letmein"

*Seriously, if you're using any of these... please try not to...*

---

### Color Constants
| Constant | Value | Usage |
|----------|-------|-------|
| `COLOR_WEAK` | `#ef4444` | Red - weak passwords |
| `COLOR_MOD` | `#f59e0b` | Orange - moderate passwords |
| `COLOR_STRONG` | `#22c55e` | Green - strong passwords |

---

### SQL_KEYWORDS
List of SQL keywords to detect injection attempts: SELECT, DROP, INSERT, DELETE, UPDATE, UNION, etc.

---

### DANGEROUS_PATTERNS
Regex patterns to detect XSS and malicious code: `<script>`, `javascript:`, `onclick=`, etc.

---

### DISPOSABLE_DOMAINS
Blocked temporary email services:
- yopmail.com
- mailinator.com
- temp-mail.org
- guerrillamail.com
- 10minutemail.com
- trashmail.com
- throwaway.email


</details>

---

<details>
<summary> 🖥️ GUI Features </summary>
<br>

### Enter Key Binding
`root.bind_all("<Return>", ...)` allows users to press Enter to trigger password analysis without clicking the button.

*bec clicking buttons is so 90s~ just hit enter!*

---

### Conditional Scrollbars
Scrollbars appear only when content exceeds the visible area:
- Message input field (web validator)
- Password generator results
- Password strength details
- Form validation results

---

### Inline Validation Feedback
Web form validator shows:
- ✓ Valid (green) - Field passes all checks
- ✗ Error (red) - Lists ALL violations separated by bullets (•)

**Note**: Sanitization warnings are no longer shown to users. All sanitization is logged silently to `data/security_log.txt` for audit purposes.

*users don't need to know the scary technical details — they just need to know if it's valid or not~ keeping it simple! ✨abstraction✨ *

---

### Tool Mutex (Local Security Tools)
The Port Scanner and Traffic Analyzer use a mutual exclusion mechanism to prevent both tools from running simultaneously:
- When a scan is active, the Traffic Analyzer tab shows a lock warning and all its controls are disabled
- When a capture is active, the Port Scanner tab shows a lock warning and all its controls are disabled
- Switching between the top-level navigation categories (e.g., to Web Based Security Tools) automatically stops any active scan or capture

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

*made with 💻 ♡ and probably too much coffee~ ☕*

*BSIT-S31101 | MO-IT139 Security Script Programming | 2026*