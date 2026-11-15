import socket
import concurrent.futures

COMMON_PORTS = [
    21, 22, 23, 25, 53,
    80, 110, 143, 443,
    3306, 3389, 8080
]

PORT_NAMES = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Remote Login)",
    25: "SMTP (Mail Transfer)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Traffic)",
    110: "POP3 (Mail Retrieval)",
    143: "IMAP (Mail Access)",
    443: "HTTPS (Secure Web Traffic)",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    8080: "HTTP Proxy/Web Service"
}


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((ip, port))

        sock.close()

        return port, (result == 0)

    except Exception:
        return port, False


def scan_ports_threaded(target):

    ip = resolve_target(target)

    if not ip:
        raise Exception("Invalid IP address or hostname")

    open_ports = []
    closed_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:

        results = executor.map(
            lambda port: scan_port(ip, port),
            COMMON_PORTS
        )

    for port, is_open in results:

        if is_open:
            open_ports.append(port)
        else:
            closed_ports.append(port)

    return open_ports, closed_ports, PORT_NAMES