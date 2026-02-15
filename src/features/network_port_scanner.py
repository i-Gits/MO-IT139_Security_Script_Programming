# src/features/network_port_scanner.py

'''References for port presets: 
1) Common Ports by Service Category: https://www.stationx.net/common-ports-cheat-sheet/
2) Game-specific ports (e.g. Steam, Valorant)
- Steam: https://help.steampowered.com/en/faqs/view/2EA8-4D75-DA21-31EB
- Valorant: https://support-valorant.riotgames.com/hc/en-us/articles/4402306473619-How-to-Set-Up-Port-Forwarding
'''

import socket

# Common Ports by Category
COMMON_PORTS_BY_CATEGORY = {
    "Web Services": [
        ("80", "HTTP"),
        ("443", "HTTPS")
    ],
    "Mail Services": [
        ("25", "SMTP"),
        ("110", "POP3"),
        ("143", "IMAP")
    ],
    "Remote Access & Management": [
        ("22", "SSH/SCP"),
        ("23", "Telnet"),
        ("3389", "RDP")
    ],
    "Directory / Authentication": [
        ("88", "Kerberos"),
        ("389", "LDAP"),
        ("464", "Kerberos password settings"),
        ("636", "LDAPS")
    ],
    "File Transfer & Sharing": [
        ("20/21", "FTP"),
        ("69", "TFTP"),
        ("445", "SMB")
    ],
    "Network Core": [
        ("53", "DNS"),
        ("67, 68", "DHCP / BOOTP"),
        ("123", "NTP")
    ],
    "Network Management & Monitoring": [
        ("161", "SNMP")
    ],
    "Communication, VoIP, and Chat": [
        ("194", "IRC"),
        ("1720", "H.323"),
        ("5060", "SIP"),
        ("5061", "SIP over TLS")
    ],
    "Legacy and Testing": [
        ("7", "Echo"),
        ("23", "Telnet")
    ]
}

# Port Presets/Dropdown Options - common ports + gaming ports
PORT_PRESETS = {
    "Select": {
        "ports": [],
        "start": "20",
        "end": "100",
        "description": "Choose a port type"
    },
    "Web Services": {
        "ports": ["80", "443"],
        "start": "80",
        "end": "443",
        "description": "HTTP and HTTPS ports"
    },
    "Mail Services": {
        "ports": ["25", "110", "143"],
        "start": "25",
        "end": "143",
        "description": "SMTP, POP3, and IMAP ports"
    },
    "Remote Access & Management": {
        "ports": ["22", "23", "3389"],
        "start": "22",
        "end": "3389",
        "description": "SSH, Telnet, and RDP ports"
    },
    "Directory / Authentication": {
        "ports": ["88", "389", "464", "636"],
        "start": "88",
        "end": "636",
        "description": "Kerberos, LDAP ports"
    },
    "File Transfer & Sharing": {
        "ports": ["20", "21", "69", "445"],
        "start": "20",
        "end": "445",
        "description": "FTP, TFTP, SMB ports"
    },
    "Network Core": {
        "ports": ["53", "67", "68", "123"],
        "start": "53",
        "end": "123",
        "description": "DNS, DHCP, NTP ports"
    },
    "Network Management & Monitoring": {
        "ports": ["161"],
        "start": "161",
        "end": "161",
        "description": "SNMP port"
    },
    "Communication, VoIP, and Chat": {
        "ports": ["194", "1720", "5060", "5061"],
        "start": "194",
        "end": "5061",
        "description": "IRC, H.323, SIP ports"
    },
    "Legacy and Testing": {
        "ports": ["7", "23"],
        "start": "7",
        "end": "23",
        "description": "Echo and Telnet ports"
    },
    "Steam": {
        "ports": ["80", "443", "27000-27100"],
        "start": "80",
        "end": "27100",
        "description": "Steam platform ports"
    },
    "Valorant": {
        "ports": ["80", "443", "7000-8000"],
        "start": "80",
        "end": "8400",
        "description": "Valorant game ports"
    }
}

# Build port-to-service mapping
def build_port_service_map():
    """Build a dictionary mapping port numbers to service names"""
    port_map = {}
    for category, ports in COMMON_PORTS_BY_CATEGORY.items():
        for port_str, service in ports:
            # Handle multiple ports like "20/21" or "67, 68"
            if '/' in port_str:
                for p in port_str.split('/'):
                    port_map[int(p.strip())] = service
            elif ',' in port_str:
                for p in port_str.split(','):
                    port_map[int(p.strip())] = service
            else:
                port_map[int(port_str)] = service
    return port_map

PORT_SERVICE_MAP = build_port_service_map()


def scan_port(host, port, timeout=0.5):
    """Scan a single port on the specified host"""
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Try to connect to the port (returns 0 if successful)
        result = sock.connect_ex((host, port))
        sock.close()
        
        return result == 0  # Port is open if result is 0
    except socket.error:
        return False


def scan_port_range(host, start_port, end_port, timeout=0.5, callback=None):
    """Scan a range of ports on the specified host"""
    results = {'open': [], 'closed': []}
    
    for port in range(start_port, end_port + 1):
        is_open = scan_port(host, port, timeout)
        
        # Add to results
        if is_open:
            results['open'].append(port)
        else:
            results['closed'].append(port)
        
        # Call callback for real-time updates
        if callback:
            callback(port, is_open)
    
    return results


def validate_host(host):
    """Validate if the host is reachable"""
    if not host or host.strip() == "":
        return False, "Please enter a valid IP address or hostname."
    
    try:
        # Try to resolve the hostname
        socket.gethostbyname(host)
        return True, None
    except socket.gaierror:
        return False, "Host unreachable or invalid hostname."
    except Exception as e:
        return False, f"Error validating host: {str(e)}"


def validate_port_range(start_str, end_str):
    """
    Validate port range input
    
    Requirements:
    - Both values must be integers
    - Starting port < Ending port
    - Range must be within 1-65535
    - No letters or special symbols
    
    Returns:
        tuple: (is_valid, start_port, end_port, error_message)
    """
    try:
        # Check if both are numeric (no letters or special symbols)
        if not start_str.isdigit():
            return False, None, None, "Start port must be a number (no letters or symbols)"
        
        if not end_str.isdigit():
            return False, None, None, "End port must be a number (no letters or symbols)"
        
        start_port = int(start_str)
        end_port = int(end_str)
        
        # Validate port range (1-65535)
        if start_port < 1:
            return False, None, None, "Start port must be at least 1"
        
        if start_port > 65535:
            return False, None, None, "Start port must not exceed 65535"
        
        if end_port < 1:
            return False, None, None, "End port must be at least 1"
        
        if end_port > 65535:
            return False, None, None, "End port must not exceed 65535"
        
        # Validate start < end
        if start_port > end_port:
            return False, None, None, "Start port must be less than end port"
        
        # Validate start == end is acceptable (scanning single port)
        if start_port == end_port:
            return True, start_port, end_port, None
        
        # Warn about very large ranges (but still allow them)
        if (end_port - start_port) > 10000:
            return False, None, None, "Port range too large (max 10,000 ports for performance)"
        
        return True, start_port, end_port, None
    
    except ValueError:
        return False, None, None, "Invalid port number format"
    except Exception as e:
        return False, None, None, f"Validation error: {str(e)}"


def get_service_name(port):
    """Get service name for a port number"""
    return PORT_SERVICE_MAP.get(port, "Unknown Service")