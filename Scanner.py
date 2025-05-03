import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor

# dictionaries to store open ports
open_tcp_ports = {}
open_udp_ports = {}


def validateIpAddress(host):
    try:
        ip_check = ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def resolve_host(host):
    if validateIpAddress(host):
        return host
    try:
        resolved_ip = socket.gethostbyname(host)
        print(f"Resolved hostname '{host}' to IP address '{resolved_ip}'")
        return resolved_ip
    except socket.gaierror:
        raise ValueError(f"Hostname '{host}' could not be resolved")



def parse_ports(port_input):
    ports = set()
    for part in port_input.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

def get_service_name(port):
    try:
        return socket.getservbyport(port)
    except:
        return "unknown"



def tcp_port_scan(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((host, port))
        sock.close()
        if result == 0:
            service = get_service_name(port)
            open_tcp_ports[port] = service
            try:
                sock.sendall(b"\n")
                banner = soc.recv(1024).decode(errors='ignore').strip()
            except:
                banner = "No banner"
            print(f"Port {port} is open | Service: '{service}' |  Banner: '{banner}")
        else:
            print(f"Port {port} is closed")
    except Exception as e:
        return (port, f"ERROR: {e}")
    finally:
        sock.close()

def udp_port_scan(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    try:
        sock.sendto(b'', (host, port))
        data, addr = sock.recvfrom(1024)
        open_udp_ports[port] = addr
        print(f"UDP Port {port} is open | Response: {data.decode(errors='ignore')}")
    except socket.timeout:
        print(f"UDP Port {port} is closed or filtered")
    except Exception as e:
        print(f"ERROR: {e}")
    finally:
        sock.close()


def run_tcp_scan(host, ports):
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda p: tcp_port_scan(host, p), ports)

def run_udp_scan(host, ports):
    with ThreadPoolExecutor(max_workers=100) as executor:
        executor.map(lambda p: udp_port_scan(host, p), ports)





def main():
    host_input = input("Please enter host name or IP address: ")
    try:
        final_ip = resolve_host(host_input)
        print(f"Scanning target: '{final_ip}'")
    except ValueError as e:
        print(e)
        return

    port_input = input("Please enter ports (e.g. 23,53,1000-1029: ")
    ports = parse_ports(port_input)
    print(f"\nPorts: {ports}")

    print("\n--- Starting TCP scan ---")
    run_tcp_scan(final_ip, ports)

    print("\n--- Starting UDP scan ---")
    run_udp_scan(final_ip, ports)

    print("--- Scan Complete ---")
    print("\n--- Open TCP ports:")
    for port, service in open_tcp_ports.items():
        print(f"Port {port}: {service}")
    print("\n--- Open UDP ports:")
    for port in open_udp_ports:
        print(f"Port {port}: response received")

if __name__ == "__main__":
    main()

