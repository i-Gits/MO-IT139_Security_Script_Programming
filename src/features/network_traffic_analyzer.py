# src/features/network_traffic_analyzer.py

import sys
import os
from datetime import datetime

# Checks if Scapy is installed
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Checks for administrator/root privileges
def check_privileges():
    
    # Check if the script is running with administrator/root privileges.
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:  # Linux/Mac
        return os.geteuid() == 0


def format_packet_info(packet):
    
    # Format packet details for display.
    packet_info = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
        'protocol': 'Unknown',
        'src_ip': 'N/A',
        'dst_ip': 'N/A',
        'src_port': 'N/A',
        'dst_port': 'N/A',
        'summary': ''
    }
    
    try:
        # Checks if packet has IP layer
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            
            # Checks protocol
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['summary'] = f"TCP {packet[TCP].flags}"
                
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                packet_info['summary'] = "UDP packet"
                
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                packet_info['summary'] = f"ICMP type={packet[ICMP].type}"
            else:
                packet_info['protocol'] = 'Other'
                packet_info['summary'] = packet.summary()
        else:
            packet_info['summary'] = packet.summary()
            
    except Exception as e:
        packet_info['summary'] = f"Error parsing packet: {str(e)}"
    
    return packet_info


def validate_filter(filter_string):
    
    # Validate BPF filter string.
    if not filter_string or filter_string.strip() == "":
        return True, None  # Empty filter is valid (captures all)
    
    filter_string = filter_string.strip().lower()
    
    # Checks if there's any valid protocol keywords
    valid_protocols = ['tcp', 'udp', 'icmp', 'ip', 'arp', 'ip6']
    valid_keywords = ['and', 'or', 'not', 'port', 'host', 'src', 'dst', 'net', 'portrange']
    
    # Checks if it contains at least one valid keyword
    tokens = filter_string.split()
    has_valid_token = any(
        token in valid_protocols or 
        token in valid_keywords or 
        token.isdigit() 
        for token in tokens
    )
    
    if not has_valid_token:
        return False, "Invalid filter. Use protocols (tcp/udp/icmp) or BPF syntax."
    
    # Checks for common mistakes
    if filter_string.count('(') != filter_string.count(')'):
        return False, "Unmatched parentheses in filter."
    
    # Check for incomplete "port" filters (e.g., "tcp and port" without number)
    if 'port' in tokens:
        port_index = tokens.index('port')
        # Check if there's a token after 'port'
        if port_index + 1 >= len(tokens):
            return False, "Incomplete filter. 'port' keyword requires a port number."
        # Check if the next token is a valid port number
        next_token = tokens[port_index + 1]
        if not next_token.isdigit():
            return False, "Invalid port number. Port must be a number (e.g., 'port 80')."
    
    return True, None


def start_packet_capture(filter_string="", packet_callback=None, stop_callback=None, count=0):
    """
    Start capturing packets with the specified filter.
        
    Shows:
        ImportError: If Scapy is not installed
        PermissionError: If not running with sufficient privileges
        ValueError: If filter is invalid
        Exception: For other capture errors
    """
    if not SCAPY_AVAILABLE:
        raise ImportError(
            "Scapy is not installed.\n\n"
            "To install Scapy, run:\n"
            "    pip install scapy\n\n"
            "After installation, restart the application."
        )
    
    if not check_privileges():
        platform_msg = ""
        if os.name == 'nt':  # Windows
            platform_msg = (
                "On Windows:\n"
                "1. Close this application\n"
                "2. Right-click Command Prompt or PowerShell\n"
                "3. Select 'Run as Administrator'\n"
                "4. Navigate to the project folder\n"
                "5. Run: python src/main.py"
            )
        else:  # Linux/Mac
            platform_msg = (
                "On Linux/Mac:\n"
                "1. Close this application\n"
                "2. Open Terminal\n"
                "3. Navigate to the project folder\n"
                "4. Run with sudo: sudo python3 src/main.py"
            )
        
        raise PermissionError(
            f"Administrator/root privileges required for packet capture.\n\n"
            f"{platform_msg}"
        )
    
    # Validates filter
    is_valid, error_msg = validate_filter(filter_string)
    if not is_valid:
        raise ValueError(error_msg)
    
    def packet_handler(packet):
        # Handler that formats and forwards packets to callback
        if stop_callback and stop_callback():
            return True  # Stop sniffing
        
        if packet_callback:
            packet_info = format_packet_info(packet)
            packet_callback(packet_info)
    
    try:
        # Start sniffing
        sniff(
            filter=filter_string if filter_string else None,
            prn=packet_handler,
            store=False,  # Don't store packets in memory
            count=count,
            stop_filter=lambda x: stop_callback() if stop_callback else False
        )
    except PermissionError:
        raise PermissionError(
            "Permission denied while accessing network interface.\n"
            "Make sure you're running with administrator/root privileges."
        )
    except Exception as e:
        error_details = str(e)
        if "permission" in error_details.lower():
            raise PermissionError(
                "Network interface access denied.\n"
                "Administrator/root privileges are required."
            )
        else:
            raise Exception(f"Capture error: {error_details}")


def get_scapy_status():

    # Get Scapy installation and privilege status.
    if not SCAPY_AVAILABLE:
        return False, False, "Scapy not installed. Install with: pip install scapy"
    
    has_privs = check_privileges()
    if not has_privs:
        if os.name == 'nt':
            return True, False, "Administrator privileges required (Run as Administrator)"
        else:
            return True, False, "Root privileges required (use sudo)"
    
    return True, True, "Ready to capture packets"