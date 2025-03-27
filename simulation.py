#!/usr/bin/env python3
"""
Simulation environment for SmirkingFace testing.
This script populates the environment with simulated hosts, services, and vulnerabilities
to demonstrate attack paths and critical hosts features.
"""

import os
import json
import random
import argparse
from datetime import datetime

from environment_state import EnvironmentStateService, Host
from attack_graph import AttackGraphService
from smirkingface import SmirkingFace

class NetworkSimulator:
    """Class to generate simulated network data for testing"""
    
    def __init__(self, data_dir="data", output_dir="output"):
        """Initialize the simulator with data directories"""
        self.data_dir = data_dir
        self.output_dir = output_dir
        
        # Create directories if they don't exist
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize environment state
        self.environment_state = EnvironmentStateService(data_dir)
        self.attack_graph = AttackGraphService(self.environment_state)
        
        # Clear any existing state
        self.environment_state.network.clear_all_hosts()
        
        # Common vulnerabilities for simulation
        self.vulnerability_templates = [
            {
                "id": "CVE-2021-44228",
                "name": "Log4Shell",
                "severity": "critical",
                "description": "Remote code execution in Log4j",
                "service": "http",
                "exploitability": 0.9
            },
            {
                "id": "CVE-2020-0796",
                "name": "SMBGhost",
                "severity": "high",
                "description": "Remote code execution in SMB protocol",
                "service": "smb",
                "exploitability": 0.8
            },
            {
                "id": "CVE-2019-0708",
                "name": "BlueKeep",
                "severity": "critical",
                "description": "Remote code execution in RDP",
                "service": "rdp",
                "exploitability": 0.9
            },
            {
                "id": "CVE-2018-7600",
                "name": "Drupalgeddon2",
                "severity": "critical",
                "description": "Remote code execution in Drupal",
                "service": "http",
                "exploitability": 0.85
            },
            {
                "id": "CVE-2017-5638",
                "name": "Apache Struts RCE",
                "severity": "critical",
                "description": "Remote code execution in Apache Struts",
                "service": "http",
                "exploitability": 0.9
            },
            {
                "id": "CVE-2014-6271",
                "name": "Shellshock",
                "severity": "critical",
                "description": "Remote code execution in bash CGI scripts",
                "service": "http",
                "exploitability": 0.85
            },
            {
                "id": "CVE-2017-0144",
                "name": "EternalBlue",
                "severity": "critical",
                "description": "Remote code execution in SMB protocol",
                "service": "smb",
                "exploitability": 0.95
            },
            {
                "id": "CVE-2019-11510",
                "name": "Pulse Secure VPN",
                "severity": "critical",
                "description": "Pre-auth arbitrary file reading vulnerability",
                "service": "vpn",
                "exploitability": 0.8
            },
            {
                "id": "CVE-2018-13379",
                "name": "Fortinet VPN",
                "severity": "high",
                "description": "Path traversal in Fortinet VPN",
                "service": "vpn",
                "exploitability": 0.75
            },
            {
                "id": "CVE-2021-26855",
                "name": "ProxyLogon",
                "severity": "critical",
                "description": "Exchange server vulnerability",
                "service": "exchange",
                "exploitability": 0.9
            }
        ]
        
        # Service templates
        self.service_templates = {
            "http": {"port": 80, "version": "Apache/2.4.41"},
            "https": {"port": 443, "version": "Apache/2.4.41 (SSL)"},
            "ssh": {"port": 22, "version": "OpenSSH 7.9"},
            "ftp": {"port": 21, "version": "vsftpd 3.0.3"},
            "smb": {"port": 445, "version": "Samba 4.3.11"},
            "rdp": {"port": 3389, "version": "Microsoft Terminal Services"},
            "mysql": {"port": 3306, "version": "MySQL 5.7.32"},
            "exchange": {"port": 443, "version": "Microsoft Exchange 2019"},
            "vpn": {"port": 443, "version": "Pulse Secure 9.0R3"},
            "telnet": {"port": 23, "version": "Linux telnetd"},
            "dns": {"port": 53, "version": "BIND 9.11.5"}
        }
    
    def generate_host(self, ip_address, hostname, access_level="none", num_services=3, num_vulns=2):
        """Generate a simulated host with services and vulnerabilities"""
        host = Host(ip_address, hostname)
        host.access_level = access_level
        
        # Add random services
        service_names = list(self.service_templates.keys())
        selected_services = random.sample(service_names, min(num_services, len(service_names)))
        
        for service_name in selected_services:
            service_info = self.service_templates[service_name].copy()
            # Add minor randomization to versions
            if random.random() > 0.7:
                version_parts = service_info["version"].split(".")
                if len(version_parts) > 2 and version_parts[-1].isdigit():
                    version_parts[-1] = str(int(version_parts[-1]) - random.randint(1, 3))
                    service_info["version"] = ".".join(version_parts)
            
            host.services[service_name] = service_info
            host.open_ports[service_info["port"]] = {"service": service_name}
        
        # Add vulnerabilities
        if num_vulns > 0:
            # Select vulnerabilities that match the host's services
            available_vulns = [v for v in self.vulnerability_templates 
                              if v["service"] in selected_services]
            
            if available_vulns:
                selected_vulns = random.sample(available_vulns, 
                                              min(num_vulns, len(available_vulns)))
                
                for vuln in selected_vulns:
                    vuln_copy = vuln.copy()
                    # Add some randomization to exploitability
                    vuln_copy["exploitability"] = round(vuln["exploitability"] * 
                                                      random.uniform(0.8, 1.0), 2)
                    host.vulnerabilities.append(vuln_copy)
        
        return host
    
    def generate_simple_network(self):
        """Generate a simple network with a few hosts"""
        # Internet-facing web server
        web_server = self.generate_host("192.168.1.10", "web-server", 
                                      access_level="none", 
                                      num_services=2, 
                                      num_vulns=1)
        self.environment_state.network.add_host(web_server)
        
        # Database server
        db_server = self.generate_host("192.168.1.20", "db-server", 
                                     access_level="none", 
                                     num_services=2, 
                                     num_vulns=1)
        self.environment_state.network.add_host(db_server)
        
        # Save the environment state
        self.environment_state.save_state()
        print(f"Created simple network with 2 hosts")
        
    def generate_complex_network(self, num_hosts=10):
        """Generate a more complex network simulation"""
        # Define network segments
        segments = {
            "dmz": {"ip_prefix": "192.168.1.", "host_range": (10, 19)},
            "web": {"ip_prefix": "192.168.2.", "host_range": (20, 29)},
            "app": {"ip_prefix": "192.168.3.", "host_range": (30, 39)},
            "db": {"ip_prefix": "192.168.4.", "host_range": (40, 49)},
            "internal": {"ip_prefix": "10.0.0.", "host_range": (50, 59)}
        }
        
        # Generate hosts for each segment
        hosts_per_segment = max(1, num_hosts // len(segments))
        total_hosts = 0
        
        for segment_name, segment_info in segments.items():
            segment_hosts = min(hosts_per_segment, 
                              segment_info["host_range"][1] - segment_info["host_range"][0] + 1)
            
            for i in range(segment_hosts):
                host_num = segment_info["host_range"][0] + i
                ip = segment_info["ip_prefix"] + str(host_num)
                hostname = f"{segment_name}-server-{i+1}"
                
                # Different segments have different characteristics
                if segment_name == "dmz":
                    # DMZ hosts - internet facing, more vulnerable
                    host = self.generate_host(ip, hostname, access_level="none", 
                                           num_services=3, num_vulns=2)
                elif segment_name == "web":
                    # Web servers - external applications
                    host = self.generate_host(ip, hostname, access_level="none", 
                                           num_services=2, num_vulns=1)
                elif segment_name == "app":
                    # Application servers - internal business logic
                    host = self.generate_host(ip, hostname, access_level="none", 
                                           num_services=3, num_vulns=1)
                elif segment_name == "db":
                    # Database servers - critical data
                    host = self.generate_host(ip, hostname, access_level="none", 
                                           num_services=2, num_vulns=1)
                elif segment_name == "internal":
                    # Internal servers - administrative, critical
                    host = self.generate_host(ip, hostname, access_level="none", 
                                           num_services=4, num_vulns=1)
                
                # Add host to environment
                self.environment_state.network.add_host(host)
                total_hosts += 1
        
        # Save the environment state
        self.environment_state.save_state()
        print(f"Created complex network with {total_hosts} hosts across {len(segments)} segments")
    
    def add_simulated_credentials(self, success_rate=0.3):
        """Add simulated credentials for some services"""
        hosts = self.environment_state.network.get_all_hosts()
        
        for host in hosts:
            for service_name in host.services:
                # Only add credentials to certain services
                if service_name in ["ssh", "ftp", "telnet", "rdp"] and random.random() < success_rate:
                    username = random.choice(["admin", "root", "user", "service", host.hostname.split('-')[0]])
                    password = random.choice(["password", "admin123", "P@ssw0rd", "123456", "welcome1"])
                    
                    # Record credentials in host data
                    if not hasattr(host, "credentials"):
                        host.credentials = {}
                    
                    host.credentials[service_name] = {
                        "username": username,
                        "password": password
                    }
                    
                    print(f"Added credentials for {service_name} on {host.hostname} ({host.ip_address})")
        
        # Save the updated environment state
        self.environment_state.save_state()
    
    def add_scan_history(self):
        """Add simulated scan history entries"""
        hosts = self.environment_state.network.get_all_hosts()
        
        for host in hosts:
            scan_data = {
                "target": host.ip_address,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "scan_type": random.choice(["quick", "full", "service"]),
                "services_found": len(host.services),
                "vulnerabilities_found": len(host.vulnerabilities)
            }
            
            self.environment_state.network.scan_history.append(scan_data)
        
        # Save the updated environment state
        self.environment_state.save_state()
        print(f"Added scan history entries for {len(hosts)} hosts")
    
    def compromise_random_hosts(self, num_hosts=2):
        """Simulate compromise of random hosts by setting access level"""
        hosts = self.environment_state.network.get_all_hosts()
        
        if not hosts or len(hosts) < num_hosts:
            print("Not enough hosts to compromise")
            return
        
        # Select random hosts to compromise
        compromised = random.sample(hosts, num_hosts)
        
        for host in compromised:
            # Set to user or admin access randomly
            host.access_level = random.choice(["user", "admin"])
            print(f"Compromised {host.hostname} ({host.ip_address}) with {host.access_level} access")
        
        # Save the updated environment state
        self.environment_state.save_state()
    
    def run_simulation(self, complexity="simple", num_hosts=10):
        """Run the full simulation setup"""
        print(f"Starting {complexity} network simulation...")
        
        # Generate network based on complexity
        if complexity == "simple":
            self.generate_simple_network()
        else:
            self.generate_complex_network(num_hosts)
        
        # Add additional simulation elements
        self.add_simulated_credentials()
        self.add_scan_history()
        
        # Compromise some hosts if using complex simulation
        if complexity != "simple":
            self.compromise_random_hosts(num_hosts=max(1, num_hosts // 5))
        
        print(f"Simulation complete. Environment data saved to {self.data_dir}")
        
        # Return the SmirkingFace instance ready to use with the simulated data
        return SmirkingFace(
            data_dir=self.data_dir,
            output_dir=self.output_dir,
            interactive=True,
            timeout=300
        )


def main():
    """Main entry point for the simulation script"""
    parser = argparse.ArgumentParser(description="SmirkingFace simulation environment generator")
    parser.add_argument("-c", "--complexity", choices=["simple", "complex"], default="simple",
                       help="Complexity of the simulated network (simple or complex)")
    parser.add_argument("-n", "--num-hosts", type=int, default=10,
                       help="Number of hosts to generate (for complex simulation)")
    parser.add_argument("-d", "--data-dir", default="data",
                       help="Data directory for storing state")
    parser.add_argument("-o", "--output-dir", default="output",
                       help="Output directory for results")
    
    args = parser.parse_args()
    
    # Create simulator
    simulator = NetworkSimulator(
        data_dir=args.data_dir,
        output_dir=args.output_dir
    )
    
    # Run simulation
    sf = simulator.run_simulation(
        complexity=args.complexity,
        num_hosts=args.num_hosts
    )
    
    # Run SmirkingFace in interactive mode
    sf.interactive_mode()


if __name__ == "__main__":
    main() 