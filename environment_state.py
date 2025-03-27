from typing import Dict, List, Optional, Set, Union
import json
import os
from datetime import datetime
import ipaddress


class Host:
    """Represents a discovered host in the network"""
    
    def __init__(self, ip_address: str, hostname: str = ""):
        self.ip_address = ip_address
        self.hostname = hostname
        self.open_ports: Dict[int, Dict] = {}
        self.os_info: Dict = {}
        self.vulnerabilities: List[Dict] = []
        self.access_level: str = "none"  # none, user, admin, system
        self.services: Dict[str, Dict] = {}
        self.last_seen: str = datetime.now().isoformat()
        self.credentials: Dict[str, Dict] = {}  # Store credentials for services
    
    def to_dict(self) -> Dict:
        """Convert Host to dictionary for serialization"""
        return {
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "open_ports": self.open_ports,
            "os_info": self.os_info,
            "vulnerabilities": self.vulnerabilities,
            "access_level": self.access_level,
            "services": self.services,
            "last_seen": self.last_seen,
            "credentials": self.credentials
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Host':
        """Create Host from dictionary"""
        host = cls(data["ip_address"], data.get("hostname", ""))
        host.open_ports = data.get("open_ports", {})
        host.os_info = data.get("os_info", {})
        host.vulnerabilities = data.get("vulnerabilities", [])
        host.access_level = data.get("access_level", "none")
        host.services = data.get("services", {})
        host.last_seen = data.get("last_seen", datetime.now().isoformat())
        host.credentials = data.get("credentials", {})
        return host
    
    def add_service(self, name: str, port: int, version: str = "", details: Dict = None) -> None:
        """Add a detected service to the host"""
        if details is None:
            details = {}
        
        self.services[name] = {
            "port": port,
            "version": version,
            "details": details
        }
        
        # Also update the open ports list
        self.open_ports[port] = {
            "service": name,
            "version": version
        }
    
    def add_vulnerability(self, vuln_id: str, name: str, severity: str, 
                         description: str, service: str = None) -> None:
        """Add a detected vulnerability to the host"""
        vulnerability = {
            "id": vuln_id,
            "name": name,
            "severity": severity,
            "description": description,
            "service": service,
            "discovered_date": datetime.now().isoformat()
        }
        self.vulnerabilities.append(vulnerability)
    
    def update_access_level(self, level: str) -> None:
        """Update the access level for this host"""
        valid_levels = ["none", "user", "admin", "system"]
        if level not in valid_levels:
            raise ValueError(f"Invalid access level. Must be one of: {valid_levels}")
        self.access_level = level


class Network:
    """Manages the collection of hosts in a network"""
    
    def __init__(self, name: str = "Default Network"):
        self.name = name
        self.hosts: Dict[str, Host] = {}
        self.scan_history: List[Dict] = []
    
    def add_host(self, host: Host) -> None:
        """Add or update a host in the network"""
        self.hosts[host.ip_address] = host
    
    def get_host(self, ip_address: str) -> Optional[Host]:
        """Get a host by IP address"""
        return self.hosts.get(ip_address)
    
    def find_host_by_ip(self, ip_address: str) -> Optional[Host]:
        """Find a host by IP address"""
        return self.get_host(ip_address)
    
    def get_all_hosts(self) -> List[Host]:
        """Get all hosts in the network"""
        return list(self.hosts.values())
    
    def clear_all_hosts(self) -> None:
        """Clear all hosts from the network"""
        self.hosts.clear()
        print("Cleared all hosts from the network")
    
    def add_scan_result(self, scan_result: Dict) -> None:
        """Add a scan result to the history"""
        self.scan_history.append({
            "timestamp": datetime.now().isoformat(),
            "result": scan_result
        })
    
    def to_dict(self) -> Dict:
        """Convert Network to dictionary for serialization"""
        return {
            "name": self.name,
            "hosts": {ip: host.to_dict() for ip, host in self.hosts.items()},
            "scan_history": self.scan_history
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Network':
        """Create Network from dictionary"""
        network = cls(data.get("name", "Default Network"))
        for ip, host_data in data.get("hosts", {}).items():
            network.hosts[ip] = Host.from_dict(host_data)
        network.scan_history = data.get("scan_history", [])
        return network


class EnvironmentStateService:
    """Service for managing and persisting the state of the environment"""
    
    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.network = Network()
        self.load_state()
    
    def load_state(self) -> None:
        """Load state from disk if available"""
        network_file = os.path.join(self.data_dir, "network_state.json")
        if os.path.exists(network_file):
            try:
                with open(network_file, 'r') as f:
                    data = json.load(f)
                    self.network = Network.from_dict(data)
                print(f"Loaded environment state with {len(self.network.hosts)} hosts")
            except Exception as e:
                print(f"Error loading environment state: {e}")
                self.network = Network()
    
    def save_state(self) -> None:
        """Save state to disk"""
        network_file = os.path.join(self.data_dir, "network_state.json")
        try:
            with open(network_file, 'w') as f:
                json.dump(self.network.to_dict(), f, indent=2)
            print("Environment state saved successfully")
        except Exception as e:
            print(f"Error saving environment state: {e}")
    
    def update_from_scan(self, scan_data: Dict) -> None:
        """Update the environment state from a scan result"""
        if not scan_data:
            return
        
        target = scan_data.get("metadata", {}).get("target", "")
        if not target:
            return
        
        # Create or update host
        host = self.network.get_host(target) or Host(target)
        
        # Update services from detected_services
        for service_name, info in scan_data.get("detected_services", {}).items():
            port = info.get("port", 0)
            version_info = info.get("version", {})
            version_str = version_info.get("version", "Unknown")
            
            host.add_service(
                name=service_name,
                port=port,
                version=version_str,
                details=info
            )
        
        # Add any discovered vulnerabilities from exploits section
        for service_name, exploits in scan_data.get("exploits", {}).items():
            for exploit in exploits:
                host.add_vulnerability(
                    vuln_id=exploit.get("EDB-ID", "unknown"),
                    name=exploit.get("Title", "Unknown Vulnerability"),
                    severity="Medium",  # Default, would need to be determined based on CVSS or similar
                    description=exploit.get("Description", ""),
                    service=service_name
                )
        
        # Update host in network
        self.network.add_host(host)
        
        # Add scan to history
        self.network.add_scan_result(scan_data)
        
        # Save updated state
        self.save_state() 