# src/features/network_port_scanner.py

import socket

def scan_port(host, port, timeout=0.5):

    # Scan a single port on the specified host
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

    # Scan a range of ports on the specified host.
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

    # Validate if the host is reachable.
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
    
    
def get_common_ports() -> List[int]:
    """Example helper — can be extended / loaded from file later"""
    return [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
            1433, 3306, 3389, 5432, 5900, 8080, 8443]
