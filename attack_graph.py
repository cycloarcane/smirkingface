from typing import Dict, List, Set, Tuple, Optional
import networkx as nx
from collections import defaultdict

from environment_state import Host, Network, EnvironmentStateService

class AttackStep:
    """Represents a single step in an attack path"""
    
    def __init__(self, 
                 source_host: str, 
                 target_host: str, 
                 vulnerability: Dict = None,
                 technique: str = None,
                 probability: float = 0.0,
                 impact: float = 0.0):
        self.source_host = source_host
        self.target_host = target_host 
        self.vulnerability = vulnerability
        self.technique = technique
        self.probability = probability  # 0.0 to 1.0
        self.impact = impact  # 0.0 to 1.0
    
    def to_dict(self) -> Dict:
        """Convert AttackStep to dictionary for serialization"""
        return {
            "source_host": self.source_host,
            "target_host": self.target_host,
            "vulnerability": self.vulnerability,
            "technique": self.technique,
            "probability": self.probability,
            "impact": self.impact
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'AttackStep':
        """Create AttackStep from dictionary"""
        return cls(
            source_host=data["source_host"],
            target_host=data["target_host"],
            vulnerability=data.get("vulnerability"),
            technique=data.get("technique"),
            probability=data.get("probability", 0.0),
            impact=data.get("impact", 0.0)
        )


class AttackPath:
    """Represents a sequence of attack steps from initial access to goal"""
    
    def __init__(self, steps: List[AttackStep] = None):
        self.steps = steps or []
    
    def add_step(self, step: AttackStep) -> None:
        """Add a step to the attack path"""
        self.steps.append(step)
    
    @property
    def source_host(self) -> str:
        """Get the initial source host in the attack path"""
        if not self.steps:
            return None
        return self.steps[0].source_host
    
    @property
    def target_host(self) -> str:
        """Get the final target host in the attack path"""
        if not self.steps:
            return None
        return self.steps[-1].target_host
    
    @property
    def length(self) -> int:
        """Get the number of steps in the attack path"""
        return len(self.steps)
    
    @property
    def total_probability(self) -> float:
        """Calculate the overall probability of success for this path"""
        if not self.steps:
            return 0.0
        
        # Multiply probabilities together since all steps must succeed
        prob = 1.0
        for step in self.steps:
            prob *= step.probability
        return prob
    
    @property
    def max_impact(self) -> float:
        """Get the maximum impact of any step in this path"""
        if not self.steps:
            return 0.0
        
        return max(step.impact for step in self.steps)
    
    def to_dict(self) -> Dict:
        """Convert AttackPath to dictionary for serialization"""
        return {
            "steps": [step.to_dict() for step in self.steps],
            "source_host": self.source_host,
            "target_host": self.target_host,
            "length": self.length,
            "total_probability": self.total_probability,
            "max_impact": self.max_impact
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'AttackPath':
        """Create AttackPath from dictionary"""
        path = cls()
        for step_data in data.get("steps", []):
            path.add_step(AttackStep.from_dict(step_data))
        return path


class AttackGraphService:
    """Service for building and querying attack graphs based on network state"""
    
    def __init__(self, environment_state_service: EnvironmentStateService):
        self.environment_state_service = environment_state_service
        self.graph = nx.DiGraph()  # Directed graph representing attack paths
        self.vulnerability_weights = {
            "High": 0.9,
            "Medium": 0.6,
            "Low": 0.3,
            "Unknown": 0.5
        }
    
    def build_attack_graph(self) -> None:
        """Build the attack graph based on current environment state"""
        # Clear existing graph
        self.graph.clear()
        
        # Get all hosts in the network
        hosts = self.environment_state_service.network.get_all_hosts()
        
        # Add nodes for each host
        for host in hosts:
            self.graph.add_node(host.ip_address, host=host.to_dict())
        
        # Add edges between hosts based on vulnerabilities and network connectivity
        for source_host in hosts:
            for target_host in hosts:
                if source_host.ip_address == target_host.ip_address:
                    continue  # Skip self-connections
                
                # Check for potential attack paths between hosts
                attack_vectors = self._find_attack_vectors(source_host, target_host)
                
                for vector in attack_vectors:
                    # Add edge with attack vector as attribute
                    self.graph.add_edge(
                        source_host.ip_address, 
                        target_host.ip_address,
                        **vector
                    )
    
    def _find_attack_vectors(self, source_host: Host, target_host: Host) -> List[Dict]:
        """Find potential attack vectors from source to target host"""
        attack_vectors = []
        
        # Check for vulnerabilities in target host services
        for service_name, service_info in target_host.services.items():
            for vulnerability in target_host.vulnerabilities:
                if vulnerability.get("service") == service_name:
                    # This is a potential attack vector
                    severity = vulnerability.get("severity", "Unknown")
                    probability = self.vulnerability_weights.get(severity, 0.5)
                    
                    attack_vectors.append({
                        "type": "exploit",
                        "vulnerability": vulnerability,
                        "service": service_name,
                        "probability": probability,
                        "impact": probability,  # Simplified - impact equals probability
                        "description": f"Exploit {vulnerability['name']} in {service_name}"
                    })
        
        # If no specific vulnerabilities, check for common attack vectors
        if not attack_vectors and self._hosts_in_same_subnet(source_host, target_host):
            # Check for SSH service with potential for brute force
            if "ssh" in target_host.services:
                attack_vectors.append({
                    "type": "brute_force",
                    "service": "ssh",
                    "probability": 0.3,
                    "impact": 0.7,
                    "description": "SSH brute force attempt"
                })
            
            # Check for FTP service with potential for anonymous login
            if "ftp" in target_host.services:
                attack_vectors.append({
                    "type": "anonymous_login",
                    "service": "ftp",
                    "probability": 0.4,
                    "impact": 0.5,
                    "description": "FTP anonymous login attempt"
                })
        
        return attack_vectors
    
    def _hosts_in_same_subnet(self, host1: Host, host2: Host) -> bool:
        """Check if two hosts are in the same subnet (simplified)"""
        # This is a simplified check - would need more sophisticated logic in real environment
        try:
            ip1 = host1.ip_address.split('.')
            ip2 = host2.ip_address.split('.')
            return ip1[0:3] == ip2[0:3]  # Check if first 3 octets match (class C)
        except:
            return False
    
    def get_possible_attack_paths(self, target_host: str, 
                                  max_length: int = 5) -> List[AttackPath]:
        """Find all possible attack paths to a target host"""
        # Make sure graph is up-to-date
        self.build_attack_graph()
        
        attack_paths = []
        hosts = self.environment_state_service.network.get_all_hosts()
        
        # Find paths from each host to target
        for source_host in hosts:
            if source_host.ip_address == target_host:
                continue  # Skip self-paths
            
            try:
                # Find all simple paths (no cycles) from source to target
                paths = list(nx.all_simple_paths(
                    self.graph, 
                    source=source_host.ip_address, 
                    target=target_host,
                    cutoff=max_length
                ))
                
                # Convert paths to AttackPath objects
                for path in paths:
                    attack_path = AttackPath()
                    
                    # Add each step in the path
                    for i in range(len(path) - 1):
                        source = path[i]
                        target = path[i + 1]
                        
                        # Get edge data for this step
                        edge_data = self.graph.get_edge_data(source, target)
                        
                        # Create an AttackStep
                        step = AttackStep(
                            source_host=source,
                            target_host=target,
                            vulnerability=edge_data.get("vulnerability"),
                            technique=edge_data.get("type"),
                            probability=edge_data.get("probability", 0.0),
                            impact=edge_data.get("impact", 0.0)
                        )
                        
                        attack_path.add_step(step)
                    
                    attack_paths.append(attack_path)
            
            except nx.NetworkXNoPath:
                # No path from this source to target
                continue
        
        # Sort paths by probability (highest first)
        attack_paths.sort(key=lambda p: p.total_probability, reverse=True)
        
        return attack_paths
    
    def find_critical_hosts(self) -> List[Dict]:
        """Find hosts that are critical in the attack graph (high centrality)"""
        # Make sure graph is up-to-date
        self.build_attack_graph()
        
        # Calculate betweenness centrality 
        centrality = nx.betweenness_centrality(self.graph)
        
        # Get hosts with centrality scores
        critical_hosts = [
            {
                "ip_address": ip, 
                "centrality": score,
                "host_data": self.graph.nodes[ip].get("host", {})
            }
            for ip, score in centrality.items()
            if score > 0  # Only include hosts that are on some path
        ]
        
        # Sort by centrality (highest first)
        critical_hosts.sort(key=lambda x: x["centrality"], reverse=True)
        
        return critical_hosts 