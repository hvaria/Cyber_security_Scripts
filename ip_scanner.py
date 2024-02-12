from scapy.all import ARP, Ether, srp
from mac_vendor_lookup import MacLookup
import socket
import logging
import random
import subprocess

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

nmap_path = r'C:\Program Files\Nmap\nmap.exe'  # Adjust as necessary for your installation path
# result = subprocess.run([nmap_path, '-O', '--osscan-guess', ip], capture_output=True, text=True)


# Common port to service name mapping
PORT_TO_SERVICE = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    443: 'HTTPS',
    3306: 'MySQL',
    3389: 'RDP',
    8080: 'HTTP-Alt',
}

def nmap_os_detection(ip):
    try:
        result = subprocess.run([nmap_path, '-O', '--osscan-guess', ip], capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout
        else:
            logging.error(f"Nmap scan error for {ip}: {result.stderr}")
            return "Nmap OS detection encountered an error"
    except subprocess.TimeoutExpired:
        logging.warning(f"Nmap OS detection timed out for {ip}")
    except Exception as e:
        logging.error(f"Error during Nmap OS detection for {ip}: {e}")
    return "Nmap OS detection failed"


def scan(ip):
    logging.info(f"Starting scan on subnet: {ip}")
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients = []
    for element in answered_list:
        ip_address = element[1].psrc
        logging.info(f"Scanning services and OS for {ip_address}")
        services = scan_services(ip_address)
        os_info = nmap_os_detection(ip_address)  # Perform OS detection
        client_info = {
            'ip': ip_address,
            'mac': element[1].hwsrc,
            'vendor': get_vendor(element[1].hwsrc),
            'services': services,
            'os_info': os_info  # Add OS information
        }
        clients.append(client_info)
    return clients

def get_vendor(mac_address):
    try:
        vendor = MacLookup().lookup(mac_address)
        logging.info(f"Found vendor: {vendor} for MAC {mac_address}")
        return vendor
    except:
        logging.warning(f"Vendor lookup failed for MAC {mac_address}")
        return "Unknown"

def scan_services(ip, num_ports=10):
    logging.info(f"Starting service scan on {ip} with {num_ports} random ports")
    detected_services = {}
    scanned_ports = random.sample(range(1, 65536), num_ports)  # Generate random ports without repetition
    for port in scanned_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service_name = PORT_TO_SERVICE.get(port, 'Unknown')
                detected_services[port] = service_name
                logging.info(f"Port {port} is open on {ip} ({service_name})")
            sock.close()
        except Exception as e:
            logging.error(f"Error scanning port {port} on {ip}: {e}")
    return detected_services

def print_result(results_list):
    print(f"{'IP Address':<15} {'MAC Address':<20} {'Vendor':<40} {'OS Info':<15} {'Services'}")
    print("-" * 110)

    for client in results_list:
        ip = client['ip']
        mac = client['mac']
        vendor = client['vendor'] if client['vendor'] else 'NaN'
        os_info = client.get('os_info', 'Unknown')
        services = ', '.join([f"{port}: {status}" for port, status in client.get('services', {}).items()])
        print(f"{ip:<15} {mac:<20} {vendor:<40} {os_info:<15} {services}")

# Example usage
network = "192.168.1.1/24"
scan_results = scan(network)
print_result(scan_results)
