from typing import Dict, List, Any, Optional, Union
import json
import os
import subprocess
from abc import ABC, abstractmethod

from environment_state import EnvironmentStateService, Host
from attack_graph import AttackGraphService, AttackPath

class Action(ABC):
    """Base class for all actions that can be performed"""
    
    @abstractmethod
    def execute(self) -> Dict:
        """Execute the action and return the result"""
        pass
    
    @abstractmethod
    def to_dict(self) -> Dict:
        """Convert the action to a dictionary for serialization"""
        pass
    
    @classmethod
    @abstractmethod
    def from_dict(cls, data: Dict) -> 'Action':
        """Create an action from a dictionary"""
        pass


class ScanNetworkAction(Action):
    """Action to scan a network or host"""
    
    def __init__(self, target: str, scan_type: str = "full"):
        self.target = target
        self.scan_type = scan_type  # full, quick, service
        self.result = None
    
    def execute(self) -> Dict:
        """Execute the network scan"""
        # Check if target is valid
        if not self._validate_target():
            return {
                "success": False,
                "message": f"Invalid target: {self.target}",
                "data": None
            }
        
        # Build the nmap command based on scan type
        if self.scan_type == "quick":
            cmd = f"nmap {self.target} -F -oX -"  # Fast scan
        elif self.scan_type == "service":
            cmd = f"nmap {self.target} -sV -oX -"  # Service detection
        else:  # full scan
            cmd = f"nmap {self.target} -p- -sC -sV -oX -"  # Full scan with scripts and service detection
        
        try:
            # Execute the nmap command
            process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                return {
                    "success": False,
                    "message": f"Nmap scan failed: {stderr.decode()}",
                    "data": None
                }
            
            # Process the raw output without relying on main.py
            raw_output = stdout.decode()
            
            # Build scan result dictionary
            import datetime
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            scan_data = {
                "metadata": {
                    "timestamp": timestamp,
                    "target": self.target,
                    "scan_type": self.scan_type,
                    "command": cmd
                },
                "raw_output": raw_output
            }
            
            # Process scan results with our own implementation instead of relying on exploittest.py
            import xml.etree.ElementTree as ET
            import io
            
            # Create a simplified ServiceScanner class to handle the parsing
            class SimpleServiceScanner:
                """Simplified service scanner for parsing nmap output"""
                COMMON_SERVICES = {
                    'ftp': [20, 21],
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
                
                def __init__(self, target):
                    self.target = target
                
                def parse_nmap_output(self, scan_data):
                    """Parse nmap XML output to identify running services"""
                    services = {}
                    raw_output = scan_data.get('raw_output', '')
                    
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
                                        
                                        # Find the canonical service name
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
                
                def test_services(self, detected_services):
                    """Simple mock implementation for service testing"""
                    return {}  # Not implementing full service testing for simplicity
            
            # Use our simplified service scanner
            service_scanner = SimpleServiceScanner(self.target)
            scan_data["detected_services"] = service_scanner.parse_nmap_output(scan_data)
            scan_data["service_results"] = service_scanner.test_services(scan_data["detected_services"])
            
            # Empty exploits dict since we're not implementing searchsploit integration for simplicity
            scan_data["exploits"] = {}
            
            self.result = scan_data
            
            return {
                "success": True,
                "message": f"Scan of {self.target} completed successfully",
                "data": scan_data
            }
        
        except Exception as e:
            return {
                "success": False,
                "message": f"Error during scan: {str(e)}",
                "data": None
            }
    
    def _validate_target(self) -> bool:
        """Validate if the target is a valid IP address or domain name"""
        import re
        import ipaddress
        
        try:
            # Check if valid IP address
            ipaddress.ip_address(self.target)
            return True
        except ValueError:
            # Check if valid domain name
            domain_pattern = r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$'
            if re.match(domain_pattern, self.target):
                return True
            return False
    
    def to_dict(self) -> Dict:
        """Convert the action to a dictionary"""
        return {
            "action_type": "scan_network",
            "target": self.target,
            "scan_type": self.scan_type,
            "result": self.result
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'ScanNetworkAction':
        """Create a ScanNetworkAction from a dictionary"""
        action = cls(
            target=data["target"],
            scan_type=data.get("scan_type", "full")
        )
        action.result = data.get("result")
        return action


class TestCredentialsAction(Action):
    """Action to test credentials on a target host"""
    
    def __init__(self, target: str, service: str, 
                username: str = None, password: str = None,
                use_common_credentials: bool = False):
        self.target = target
        self.service = service.lower()  # ssh, ftp, http, etc.
        self.username = username
        self.password = password
        self.use_common_credentials = use_common_credentials
        self.result = None
    
    def execute(self) -> Dict:
        """Test credentials on the target service"""
        if self.service == "ssh":
            return self._test_ssh()
        elif self.service == "ftp":
            return self._test_ftp()
        elif self.service in ["http", "https"]:
            return self._test_http()
        else:
            return {
                "success": False,
                "message": f"Unsupported service for credential testing: {self.service}",
                "data": None
            }
    
    def _test_ssh(self) -> Dict:
        """Test SSH credentials"""
        import paramiko
        
        credentials_to_try = []
        
        # Add provided credentials if available
        if self.username and self.password:
            credentials_to_try.append((self.username, self.password))
        
        # Add common credentials if requested
        if self.use_common_credentials:
            common_credentials = [
                ("root", "root"),
                ("root", "password"),
                ("root", "admin"),
                ("admin", "admin"),
                ("admin", "password"),
                ("user", "user"),
                ("user", "password")
            ]
            credentials_to_try.extend(common_credentials)
        
        # Test each set of credentials
        for username, password in credentials_to_try:
            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(self.target, port=22, username=username, password=password, timeout=5)
                ssh.close()
                
                # If we get here, login was successful
                result = {
                    "success": True,
                    "service": "ssh",
                    "username": username,
                    "password": password
                }
                self.result = result
                
                return {
                    "success": True,
                    "message": f"SSH login successful with {username}:{password}",
                    "data": result
                }
            
            except Exception as e:
                # Login failed, continue to next credential
                continue
        
        # If we get here, all credentials failed
        self.result = {
            "success": False,
            "service": "ssh",
            "message": "All credentials failed"
        }
        
        return {
            "success": False,
            "message": "SSH login failed with all credentials",
            "data": self.result
        }
    
    def _test_ftp(self) -> Dict:
        """Test FTP credentials"""
        import ftplib
        
        credentials_to_try = []
        
        # Add provided credentials if available
        if self.username and self.password:
            credentials_to_try.append((self.username, self.password))
        
        # Always try anonymous login for FTP
        credentials_to_try.append(("anonymous", "anonymous@example.com"))
        
        # Add common credentials if requested
        if self.use_common_credentials:
            common_credentials = [
                ("root", "root"),
                ("root", "password"),
                ("admin", "admin"),
                ("admin", "password"),
                ("ftp", "ftp")
            ]
            credentials_to_try.extend(common_credentials)
        
        # Test each set of credentials
        for username, password in credentials_to_try:
            try:
                ftp = ftplib.FTP()
                ftp.connect(self.target, timeout=5)
                ftp.login(username, password)
                
                # Get directory listing to verify access
                files = []
                ftp.retrlines('LIST', files.append)
                
                ftp.quit()
                
                # If we get here, login was successful
                result = {
                    "success": True,
                    "service": "ftp",
                    "username": username,
                    "password": password,
                    "files": files[:10]  # Just include first 10 files in result
                }
                self.result = result
                
                return {
                    "success": True,
                    "message": f"FTP login successful with {username}:{password}",
                    "data": result
                }
            
            except Exception as e:
                # Login failed, continue to next credential
                continue
        
        # If we get here, all credentials failed
        self.result = {
            "success": False,
            "service": "ftp",
            "message": "All credentials failed"
        }
        
        return {
            "success": False,
            "message": "FTP login failed with all credentials",
            "data": self.result
        }
    
    def _test_http(self) -> Dict:
        """Test HTTP Basic Auth credentials"""
        import requests
        
        credentials_to_try = []
        
        # Add provided credentials if available
        if self.username and self.password:
            credentials_to_try.append((self.username, self.password))
        
        # Add common credentials if requested
        if self.use_common_credentials:
            common_credentials = [
                ("admin", "admin"),
                ("admin", "password"),
                ("root", "root"),
                ("root", "password"),
                ("user", "user")
            ]
            credentials_to_try.extend(common_credentials)
        
        # Determine protocol
        protocol = "https" if self.service == "https" else "http"
        
        # Test each set of credentials
        for username, password in credentials_to_try:
            try:
                response = requests.get(
                    f"{protocol}://{self.target}",
                    auth=(username, password),
                    verify=False,
                    timeout=5
                )
                
                # Check for successful authentication
                if response.status_code == 200:
                    result = {
                        "success": True,
                        "service": self.service,
                        "username": username,
                        "password": password,
                        "status_code": response.status_code
                    }
                    self.result = result
                    
                    return {
                        "success": True,
                        "message": f"HTTP authentication successful with {username}:{password}",
                        "data": result
                    }
            
            except Exception as e:
                # Request failed, continue to next credential
                continue
        
        # If we get here, all credentials failed
        self.result = {
            "success": False,
            "service": self.service,
            "message": "All credentials failed"
        }
        
        return {
            "success": False,
            "message": f"{self.service.upper()} authentication failed with all credentials",
            "data": self.result
        }
    
    def to_dict(self) -> Dict:
        """Convert the action to a dictionary"""
        return {
            "action_type": "test_credentials",
            "target": self.target,
            "service": self.service,
            "username": self.username,
            "password": self.password,
            "use_common_credentials": self.use_common_credentials,
            "result": self.result
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'TestCredentialsAction':
        """Create a TestCredentialsAction from a dictionary"""
        action = cls(
            target=data["target"],
            service=data["service"],
            username=data.get("username"),
            password=data.get("password"),
            use_common_credentials=data.get("use_common_credentials", False)
        )
        action.result = data.get("result")
        return action


class ActionPlanner:
    """Service for translating high-level tasks into specific actions"""
    
    def __init__(self, 
                 environment_state_service: EnvironmentStateService, 
                 attack_graph_service: AttackGraphService):
        self.environment_state_service = environment_state_service
        self.attack_graph_service = attack_graph_service
        self.actions_history: List[Action] = []
    
    def execute_action(self, action: Action) -> Dict:
        """Execute an action and record it in history"""
        result = action.execute()
        
        # Update environment state if action successful
        if result["success"] and action.__class__.__name__ == "ScanNetworkAction":
            self.environment_state_service.update_from_scan(result["data"])
        
        # Record action in history
        self.actions_history.append(action)
        
        return result
    
    def scan_network(self, target: str, scan_type: str = "full") -> Dict:
        """High-level task to scan a network or host"""
        action = ScanNetworkAction(target, scan_type)
        return self.execute_action(action)
    
    def test_credentials(self, target: str, service: str, 
                        username: str = None, password: str = None,
                        use_common_credentials: bool = False) -> Dict:
        """High-level task to test credentials on a target host"""
        action = TestCredentialsAction(target, service, username, password, use_common_credentials)
        return self.execute_action(action)
    
    def suggest_next_actions(self, target_host: str = None) -> List[Dict]:
        """Suggest possible next actions based on current environment state"""
        suggestions = []
        
        # Get all hosts
        hosts = self.environment_state_service.network.get_all_hosts()
        
        # If no hosts, suggest scanning
        if not hosts:
            suggestions.append({
                "action": "scan_network",
                "target": target_host or "127.0.0.1",
                "reason": "No hosts discovered yet, initial scanning recommended"
            })
            return suggestions
        
        # If target host specified, focus on it
        if target_host:
            target = self.environment_state_service.network.find_host_by_ip(target_host)
            if not target:
                suggestions.append({
                    "action": "scan_network",
                    "target": target_host,
                    "reason": f"Target host {target_host} not found in environment, scanning recommended"
                })
                return suggestions
            
            # Check for servicess with potential credential testing
            for service_name in target.services:
                if service_name in ["ssh", "ftp", "http", "https"]:
                    suggestions.append({
                        "action": "test_credentials",
                        "target": target_host,
                        "service": service_name,
                        "reason": f"{service_name.upper()} service detected on host, credential testing recommended"
                    })
            
            # Check for vulnerabilities to exploit
            if target.vulnerabilities:
                for vuln in target.vulnerabilities:
                    suggestions.append({
                        "action": "exploit_vulnerability",
                        "target": target_host,
                        "vulnerability": vuln["id"],
                        "reason": f"Vulnerability {vuln['name']} detected on host"
                    })
        
        # Otherwise find critical hosts
        else:
            critical_hosts = self.attack_graph_service.find_critical_hosts()
            for host_info in critical_hosts[:3]:  # Top 3 critical hosts
                ip = host_info["ip_address"]
                suggestions.append({
                    "action": "focus_on_host",
                    "target": ip,
                    "reason": f"Host {ip} is a critical node in the attack graph"
                })
        
        return suggestions 