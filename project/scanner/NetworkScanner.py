import nmap
import socket
import argparse


def resolve_domain(domain):
    """Resolve the domain to an IP address."""
    try:
        ip = socket.gethostbyname(domain)
        print(f"Domain {domain} resolved to IP {ip}")
        return ip
    except socket.gaierror:
        print(f"Error: Could not resolve domain {domain}")
        return None


def scan_ports(ip, ports, service_version, os_fingerprint, scripts, timing):
    """Scan open ports and identify services and OS fingerprinting on a given IP address."""
    nm = nmap.PortScanner()

    # Construct the Nmap arguments based on user input
    nmap_args = ''
    
    if service_version:
        nmap_args += '-sV '
    
    if os_fingerprint:
        nmap_args += '-O '  # Add OS fingerprinting
    
    if scripts:
        nmap_args += f'--script={scripts} '
    
    if timing:
        nmap_args += f'-T{timing} '

    scan_results = nm.scan(ip, ports, nmap_args.strip())
    return scan_results


def display_nmap_format(scan_data):
    """Display scan results in a detailed Nmap-like format."""
    for host, result in scan_data.get('scan', {}).items():
        print(f"scan report for {host}")
        print(f"Host is {result.get('status', {}).get('state', 'unknown')}")
        
        for proto in result.keys():
            if proto not in ['tcp', 'udp']:
                continue
            print(f"\nPORT    STATE SERVICE   VERSION")
            ports = result[proto]
            for port in ports.keys():
                port_info = ports[port]
                service_name = port_info.get('name', 'unknown')
                state = port_info.get('state', 'unknown')
                version = port_info.get('version', '')
                
                if port == 80 and service_name == "upnp":
                  service_name = "http"

                # Handle cases where service/version might be missing
                service_display = f"{service_name:<9}" if service_name else 'unknown'
                version_display = f"{version}" if version else 'unknown'

                print(f"{port}/{proto}  {state:<8}   {service_display}   {version_display}")

                # Display additional service details, such as scripts
                if 'script' in port_info:
                    for script_name, output in port_info['script'].items():
                        print(f"| {script_name}:")
                        print(f"|_ {output.strip()}")

        # Display OS fingerprinting results
        if 'osmatch' in result:
            print("\nOS and Service detection performed.")
            for osmatch in result['osmatch']:
                print(f"OS: {osmatch['name']} (Accuracy: {osmatch['accuracy']}%)")
        else:
            print("Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port")

        print(f"Scan done: 1 IP address (1 host up) scanned in {scan_data['nmap']['scanstats']['elapsed']} seconds")


def main():
    parser = argparse.ArgumentParser(description="Network Scanner similar to Nmap")
    
    # Define command-line arguments
    parser.add_argument("target", help="IP address or domain to scan")
    parser.add_argument("-p", "--ports", help="Port range (e.g., -p 0-65535 or -p-)", default="1-65535")
    parser.add_argument("-sV", "--service_version", help="Enable service/version detection", action="store_true")
    parser.add_argument("-O", "--os_fingerprint", help="Enable OS fingerprinting", action="store_true")
    parser.add_argument("-sC", "--default_scripts", help="Enable default scripts", action="store_true")
    parser.add_argument("-T", "--timing", help="Set timing template (1-5)", type=int, choices=range(1, 6))
    parser.add_argument("--script", help="Specify a script to run (e.g., --script=vuln)", default="")
    
    # Parse the command-line arguments
    args = parser.parse_args()

    # If the target is a domain, resolve it to an IP
    if not args.target.replace('.', '').isdigit():
        ip = resolve_domain(args.target)
        if not ip:
            exit(1)
    else:
        ip = args.target

    # Perform the port scan
    port_scan_results = scan_ports(ip, args.ports, args.service_version, args.os_fingerprint, args.script, args.timing)
    
    # Display the results
    display_nmap_format(port_scan_results)


if __name__ == "__main__":
    main()

