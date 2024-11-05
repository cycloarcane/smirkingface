import subprocess
import json
from datetime import datetime
import os
import re
import ipaddress
from typing import Optional, Dict, Union, List
import ftplib
import smtplib
import poplib
import imaplib
import requests
import ldap3
import paramiko
import socket
from contextlib import closing
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
import xml.etree.ElementTree as ET
from typing import Dict
import io

class ServiceScanner:
    """Class to handle service detection and basic connection testing"""
    
    COMMON_SERVICES = {
        'ftp': [20, 21],
        'sftp': [22],
        'ssh': [22],
        'telnet': [23],
        'smtp': [25, 465, 587],
        'imap': [143, 993],
        'pop3': [110, 995],
        'http': [80, 6666],
        'https': [443],
        'rdp': [3389],
        'ldap': [389, 636],
        'tftp': [69]
    }

    def __init__(self, target: str, timeout: int = 5):
        self.target = target
        self.timeout = timeout
        self.detected_services = {}

    def parse_nmap_output(self, nmap_data: Dict) -> Dict:
        """Parse nmap XML output to identify running services"""
        services = {}
        raw_output = nmap_data.get('raw_output', '')
        
        try:
            # Parse XML from the raw output
            tree = ET.parse(io.StringIO(raw_output))
            root = tree.getroot()
            
            # Find all port elements
            for host in root.findall('.//host'):
                for port in host.findall('.//port'):
                    state = port.find('state')
                    if state is not None and state.get('state') == 'open':
                        port_id = int(port.get('portid'))
                        service_elem = port.find('service')
                        
                        if service_elem is not None:
                            service_name = service_elem.get('name')
                            product = service_elem.get('product', '')
                            version = service_elem.get('version', '')
                            extra_info = service_elem.get('extrainfo', '')
                            
                            # Build version string
                            version_str = ' '.join(filter(None, [product, version, extra_info]))
                            
                            # Find the canonical service name from our COMMON_SERVICES
                            canonical_service = None
                            for common_name, ports in self.COMMON_SERVICES.items():
                                if port_id in ports or service_name in common_name:
                                    canonical_service = common_name
                                    break
                            
                            if canonical_service:
                                services[canonical_service] = {
                                    'port': port_id,
                                    'status': 'open',
                                    'version': {
                                        'name': service_name,
                                        'version': version_str if version_str else 'Unknown',
                                        'raw': f"Port {port_id}: {service_name} {version_str}"
                                    }
                                }
        
        except ET.ParseError as e:
            print(f"Error parsing XML: {e}")
            return {}
            
        return services

    def test_services(self, detected_services: Dict) -> Dict:
        """Test all detected services"""
        results = {}
        for service, info in detected_services.items():
            port = info['port']
            
            # Map service names to test methods
            test_method_map = {
                'ftp': self.test_ftp,
                'ssh': self.test_ssh,
                'http': self.test_http,
                'https': self.test_https,
                'smtp': self.test_smtp,
                'telnet': self.test_telnet
            }
            
            test_method = test_method_map.get(service)
            if test_method:
                results[service] = test_method(port)
        return results

    def test_ftp(self, port: int) -> Dict:
        """Test FTP connection and anonymous login"""
        try:
            ftp = ftplib.FTP()
            ftp.connect(self.target, port, timeout=self.timeout)
            
            # Try anonymous login
            try:
                result = ftp.login('anonymous', 'anonymous@example.com')
                ftp.quit()
                return {'success': True, 'message': 'Anonymous login successful: ' + result}
            except ftplib.error_perm as e:
                # Try to extract the specific error message
                error_msg = str(e)
                if '530' in error_msg:  # 530 is the code for login failed
                    return {'success': False, 'message': 'Anonymous login failed: ' + error_msg}
                return {'success': False, 'message': error_msg}
            
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def test_ssh(self, port: int) -> Dict:
        """Test SSH with common default credentials"""
        common_users = ['admin', 'root']
        common_passwords = ['admin', 'password', 'root']
        
        for user in common_users:
            for password in common_passwords:
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(self.target, port, user, password, timeout=self.timeout)
                    ssh.close()
                    return {'success': True, 'message': f'Login successful with {user}:{password}'}
                except Exception:
                    continue
        return {'success': False, 'message': 'No default credentials worked'}

    def test_telnet(self, port: int) -> Dict:
        """Test basic Telnet connection using raw socket"""
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    return {'success': True, 'message': 'Connection established'}
                return {'success': False, 'message': f'Connection failed with error code: {result}'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def test_smtp(self, port: int) -> Dict:
        """Test SMTP connection"""
        try:
            smtp = smtplib.SMTP(self.target, port, timeout=self.timeout)
            smtp.quit()
            return {'success': True, 'message': 'Connection established'}
        except Exception as e:
            return {'success': False, 'message': str(e)}

    def test_http(self, port: int) -> Dict:
        """Test HTTP service"""
        return self._test_http_service(port, secure=False)

    def test_https(self, port: int) -> Dict:
        """Test HTTPS service"""
        return self._test_http_service(port, secure=True)

    def _test_http_service(self, port: int, secure: bool = False) -> Dict:
        """Test HTTP/HTTPS service"""
        protocol = 'https' if secure else 'http'
        try:
            response = requests.get(
                f'{protocol}://{self.target}:{port}',
                verify=False,
                timeout=self.timeout
            )
            return {
                'success': True,
                'message': f'Status code: {response.status_code}',
                'server': response.headers.get('Server', 'Unknown')
            }
        except Exception as e:
            return {'success': False, 'message': str(e)}

def print_scan_summary(results: Dict) -> None:
    """Print a summary of scan results"""
    print("\n" + "="*50)
    print("SCAN RESULTS SUMMARY")
    print("="*50)
    
    if not results:
        print("No results available.")
        return

    # Print target information
    print(f"\nTarget: {results['metadata']['target']}")
    print(f"Scan Time: {results['metadata']['timestamp']}")
    print("\nDETECTED SERVICES:")
    print("-"*50)

    # Get and sort detected services
    services = results.get("detected_services", {})
    if not services:
        print("No services detected.")
        return

    # Print services in a numbered list
    for i, (service_name, info) in enumerate(services.items(), 1):
        version_info = info['version']
        display_name = service_name.upper()
        if version_info['version'] != 'Unknown':
            display_name += f" {version_info['version']}"
        
        print(f"{i}. {display_name} (Port {info['port']})")
        
        # If we have test results for this service, show them
        if service_name in results.get("service_results", {}):
            test_result = results["service_results"][service_name]
            status = "✓" if test_result['success'] else "✗"
            print(f"   Status: {status} {test_result['message']}")

    print("\n" + "="*50)

class NetworkScanner:
    """Main scanner class that coordinates scanning and result handling"""
    
    def __init__(self, output_dir: str = "scan_results"):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def validate_input(self, target: str) -> bool:
        """Validate if the input is a valid IP address or domain name"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            domain_pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
            if re.match(domain_pattern, target):
                return True
            return False

    def run_nmap_scan(self, target: str) -> Optional[Dict]:
        """Run complete network scan including service detection and testing"""
        if not self.validate_input(target):
            raise ValueError("Invalid IP address or domain name")

        try:
            # Run initial nmap scan
            cmd = f"nmap {target} -p- -sC -sV -oX -"
            process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                raise subprocess.SubprocessError(f"Nmap scan failed: {stderr.decode()}")

            # Create scan result dictionary
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            scan_data = {
                "metadata": {
                    "timestamp": timestamp,
                    "target": target,
                    "scan_type": "full",
                    "command": cmd
                },
                "raw_output": stdout.decode()
            }

            # Initialize service scanner and analyze results
            service_scanner = ServiceScanner(target)
            scan_data["detected_services"] = service_scanner.parse_nmap_output(scan_data)
            scan_data["service_results"] = service_scanner.test_services(scan_data["detected_services"])

            # Save results
            filename = f"{self.output_dir}/scan_{timestamp}_{target}.json"
            with open(filename, 'w') as f:
                json.dump(scan_data, f, indent=4)

            return scan_data

        except (subprocess.SubprocessError, Exception) as e:
            print(f"Error during scan: {str(e)}")
            return None

    def get_scan_history(self) -> List[Dict]:
        """Get a list of all previous scans"""
        scans = []
        for filename in os.listdir(self.output_dir):
            if filename.endswith('.json'):
                with open(os.path.join(self.output_dir, filename), 'r') as f:
                    scan_data = json.load(f)
                    scans.append(scan_data['metadata'])
        return scans

def main():
    scanner = NetworkScanner()
    
    while True:
        target = input("\nEnter IP address or domain name (or 'quit' to exit): ").strip()
        
        if target.lower() == 'quit':
            break
            
        try:
            print(f"\nStarting scan of {target}...")
            print("This may take a few minutes depending on the target...")
            results = scanner.run_nmap_scan(target)
            if results:
                print_scan_summary(results)
            else:
                print("Scan failed. Please check the target and try again.")
        except ValueError as e:
            print(f"Error: {str(e)}")
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
            continue

if __name__ == "__main__":
    main()