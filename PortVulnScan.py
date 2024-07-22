import nmap
import vulners
from tabulate import tabulate

def scan_ports(target, port_range):
    nm = nmap.PortScanner()
    nm.scan(target, port_range)  # Scanning the specified port range
    return nm

def scan_services(target, port_range):
    nm = nmap.PortScanner()
    nm.scan(target, port_range, '-sV')  # -sV flag for service/version detection
    return nm

def check_vulnerabilities(service_name, service_version, api_key):
    api = vulners.VulnersApi(api_key=api_key)
    query = f"{service_name} {service_version}"
    search_results = api.find_all(query)
    return search_results

def main():
    target = input("Enter the target IP address: ")
    port_range = input("Enter the port range (e.g., '1-1024'): ")
    api_key = input("Enter your Vulners API key: ")

    print(f"\nScanning ports on {target} within range {port_range}...\n")
    scan_result = scan_services(target, port_range)

    table_data = []
    vulnerabilities_info = []

    for host in scan_result.all_hosts():
        print(f"Host: {host} ({scan_result[host].hostname()})")
        print(f"State: {scan_result[host].state()}")
        for proto in scan_result[host].all_protocols():
            lport = scan_result[host][proto].keys()
            for port in lport:
                service = scan_result[host][proto][port]
                service_name = service['name']
                service_version = service.get('version', 'N/A')
                table_data.append([port, service_name, service_version])

                # Check for vulnerabilities
                vulnerabilities = check_vulnerabilities(service_name, service_version, api_key)
                if vulnerabilities:
                    for vuln in vulnerabilities:
                        vulnerabilities_info.append({
                            "port": port,
                            "service": service_name,
                            "version": service_version,
                            "title": vuln['title'],
                            "id": vuln['id']
                        })

    # Display the table
    print("\nPort Scan Results:")
    print(tabulate(table_data, headers=["Port", "Service", "Version"], tablefmt="pretty"))

    # Display vulnerabilities
    if vulnerabilities_info:
        print("\nDetected Vulnerabilities:")
        for vuln in vulnerabilities_info:
            print(f"Port: {vuln['port']}")
            print(f"  Service: {vuln['service']}")
            print(f"  Version: {vuln['version']}")
            print(f"  Vulnerability: {vuln['title']} ({vuln['id']})\n")
    else:
        print("\nNo vulnerabilities found.")

    # Ask user if they want to save the output
    save_output = input("Do you want to save the output to a file? (yes/no): ").strip().lower()
    if save_output == 'yes':
        file_name = input("Enter the file name to be created (without extension): ").strip()
        file_path = f"{file_name}.txt"
        
        with open(file_path, 'w') as file:
            file.write("Port Scan Results:\n")
            file.write(tabulate(table_data, headers=["Port", "Service", "Version"], tablefmt="pretty"))
            file.write("\n\nDetected Vulnerabilities:\n")
            if vulnerabilities_info:
                for vuln in vulnerabilities_info:
                    file.write(f"Port: {vuln['port']}\n")
                    file.write(f"  Service: {vuln['service']}\n")
                    file.write(f"  Version: {vuln['version']}\n")
                    file.write(f"  Vulnerability: {vuln['title']} ({vuln['id']})\n\n")
            else:
                file.write("No vulnerabilities found.\n")
        
        print(f"Output saved to {file_path}")

if __name__ == "__main__":
    main()
