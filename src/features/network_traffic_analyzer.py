# src/features/network_traffic_analyzer.py

import socket
import sys
import os   
from datetime import datetime

# Checks if Scapy is installed
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether
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
        'src_mac': 'N/A',
        'dst_mac': 'N/A',
        'src_ip': 'N/A',
        'dst_ip': 'N/A',
        'src_port': 'N/A',
        'dst_port': 'N/A',
        'summary': ''
    }
    
    try:
        # Checks if packet has IP layer
        if IP in packet:
            packet_info['src_mac'] = packet[Ether].src
            packet_info['dst_mac'] = packet[Ether].dst
            
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


def validate_filter(proto: str = "", port: str = "", host: str = "", src_ip: str = "", dst_ip: str = "") -> tuple[bool, str]:
    """
    Builds and lightly validates a BPF filter string from the GUI fields.
    Returns (is_valid: bool, filter_or_error: str)
    """
    filter_parts = []

    # Protocol
    if proto:
        proto_clean = proto.strip().lower()
        valid_protos = {'tcp', 'udp', 'icmp', 'ip', 'arp', 'ip6'}
        if proto_clean not in valid_protos:
            return False, f"Invalid protocol: '{proto_clean}'. Allowed: tcp, udp, icmp, ip, arp, ip6"
        filter_parts.append(proto_clean)

    # Port
    if port:
        port_clean = port.strip()
        if not port_clean.isdigit():
            return False, f"Invalid port: '{port_clean}' – must be a number (example: 80)"
        filter_parts.append(f"port {port_clean}")

    # General Host / IP
    if host:
        host_clean = host.strip()
        try:
            ip = socket.gethostbyname(host_clean)
            filter_parts.append(f"host {ip}")
        except socket.gaierror as e:
            return False, f"Cannot resolve host/IP: '{host_clean}' ({e})"

    # --- Source IP Filter ---
    if src_ip:
        src_clean = src_ip.strip()
        try:
            ip = socket.gethostbyname(src_clean)
            filter_parts.append(f"src host {ip}")
        except socket.gaierror as e:
            return False, f"Cannot resolve Source IP/Host: '{src_clean}' ({e})"

    # --- NEW: Destination IP Filter ---
    if dst_ip:
        dst_clean = dst_ip.strip()
        try:
            ip = socket.gethostbyname(dst_clean)
            filter_parts.append(f"dst host {ip}")
        except socket.gaierror as e:
            return False, f"Cannot resolve Destination IP/Host: '{dst_clean}' ({e})"

    # Build final string
    if not filter_parts:
        return True, ""  # empty filter = capture everything

    filter_str = " and ".join(filter_parts)

    # Very basic validity check
    if not any(kw in filter_str for kw in ['tcp','udp','icmp','ip','arp','port','host']):
        return False, "Filter has no recognizable BPF elements"

    return True, filter_str

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
    
    def packet_handler(packet):
        # Handler that formats and forwards packets to callback
        if stop_callback and stop_callback():
            return True  # Stop sniffing
        
        if packet_callback:
            packet_info = format_packet_info(packet)
            packet_callback(packet_info)

    # Store raw packets
    raw_packets = []  # Stores actual scapy packet objects for PCAP export

    def packet_handler(packet):
        if stop_callback and stop_callback():
            return True
        
        raw_packets.append(packet)  # Save the raw packet before formatting
        
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
        
    return raw_packets  # Added this so that it can return raw scapy packets for PCAP export


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