#!/usr/bin/env python3
import os
import sys
import argparse
import json
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

from environment_state import EnvironmentStateService
from attack_graph import AttackGraphService
from action_planner import ActionPlanner, ScanNetworkAction, TestCredentialsAction
from llm_integration import LLMIntegration

class SmirkingFace:
    """Main orchestrator for the SmirkingFace penetration testing framework"""
    
    def __init__(self, 
                 model_path: str = None,
                 api_type: str = "local",
                 api_base: str = None,
                 data_dir: str = "data",
                 output_dir: str = "output",
                 interactive: bool = True,
                 timeout: int = 300):
        
        # Create necessary directories
        os.makedirs(data_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize components
        self.environment_state = EnvironmentStateService(data_dir)
        self.attack_graph = AttackGraphService(self.environment_state)
        self.action_planner = ActionPlanner(self.environment_state, self.attack_graph)
        self.llm = LLMIntegration(model_path, api_type, api_base, timeout=timeout)
        
        # Configuration
        self.data_dir = data_dir
        self.output_dir = output_dir
        self.interactive = interactive
        self.current_scenario = "Initial reconnaissance"
        self.timeout = timeout
        
        print("🧠 SmirkingFace initialized")
        print(f"📊 Data directory: {data_dir}")
        print(f"📤 Output directory: {output_dir}")
        print(f"⏱️ LLM timeout: {timeout} seconds")
        
        # Load any existing state
        host_count = len(self.environment_state.network.get_all_hosts())
        if host_count > 0:
            print(f"🔍 Loaded environment with {host_count} hosts")
    
    def scan_target(self, target: str, scan_type: str = "full") -> Dict:
        """High-level function to scan a target"""
        print(f"🔍 Starting {scan_type} scan of {target}...")
        
        result = self.action_planner.scan_network(target, scan_type)
        
        if result["success"]:
            print(f"✅ Scan completed successfully")
            # Save scan results to output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{self.output_dir}/scan_{timestamp}_{target}.json"
            with open(output_file, 'w') as f:
                json.dump(result["data"], f, indent=2)
            print(f"💾 Scan results saved to {output_file}")
        else:
            print(f"❌ Scan failed: {result['message']}")
        
        return result
    
    def test_target_credentials(self, target: str, service: str, 
                               username: str = None, password: str = None,
                               use_common_credentials: bool = True) -> Dict:
        """High-level function to test credentials on a target"""
        print(f"🔑 Testing credentials for {service} on {target}...")
        
        result = self.action_planner.test_credentials(
            target, service, username, password, use_common_credentials
        )
        
        if result["success"]:
            print(f"✅ Credentials found: {result['data']['username']}:{result['data']['password']}")
            # Update host access level in environment state
            host = self.environment_state.network.find_host_by_ip(target)
            if host:
                host.update_access_level("user")  # Basic assumption - could be refined
                self.environment_state.save_state()
        else:
            print(f"❌ Credential testing failed: {result['message']}")
        
        return result
    
    def get_attack_paths(self, target: str) -> List[Dict]:
        """Get potential attack paths to a target"""
        print(f"🔄 Analyzing attack paths to {target}...")
        
        paths = self.attack_graph.get_possible_attack_paths(target)
        
        if paths:
            print(f"✅ Found {len(paths)} potential attack paths")
            for i, path in enumerate(paths[:3], 1):  # Show top 3 paths
                print(f"  Path {i}: {path.source_host} -> {path.target_host} ({len(path.steps)} steps, {path.total_probability:.2f} probability)")
            
            # Save attack paths to output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"{self.output_dir}/attack_paths_{timestamp}_{target}.json"
            with open(output_file, 'w') as f:
                json.dump([p.to_dict() for p in paths], f, indent=2)
            print(f"💾 Attack paths saved to {output_file}")
        else:
            print(f"❌ No attack paths found to {target}")
        
        return [p.to_dict() for p in paths]
    
    def get_critical_hosts(self) -> List[Dict]:
        """Get critical hosts in the environment"""
        print(f"🔍 Identifying critical hosts...")
        
        hosts = self.attack_graph.find_critical_hosts()
        
        if hosts:
            print(f"✅ Found {len(hosts)} critical hosts")
            for i, host in enumerate(hosts[:3], 1):  # Show top 3 hosts
                print(f"  Host {i}: {host['ip_address']} (centrality: {host['centrality']:.2f})")
        else:
            print(f"❌ No critical hosts found")
        
        return hosts
    
    def get_next_actions(self, target_host: str = None) -> List[Dict]:
        """Get suggestions for next actions"""
        suggestions = self.action_planner.suggest_next_actions(target_host)
        
        if suggestions:
            print(f"💡 Suggested next actions:")
            for i, suggestion in enumerate(suggestions, 1):
                print(f"  {i}. {suggestion['action']} on {suggestion['target']}")
                print(f"     Reason: {suggestion['reason']}")
        else:
            print(f"❌ No suggested actions available")
        
        return suggestions
    
    def process_llm_action(self, scenario: str) -> Dict:
        """
        Use LLM to determine and execute next action.
        
        Args:
            scenario: Description of current scenario and goal
            
        Returns:
            Result of action execution
        """
        print(f"🧠 Analyzing scenario: {scenario}")
        
        # Format environment state for LLM
        env_state = self.llm.format_environment_for_llm(self.environment_state)
        
        # Get action plan from LLM
        llm_result = self.llm.query_for_action(scenario, env_state)
        
        if not llm_result["success"]:
            error_msg = llm_result.get("error", "Unknown error")
            
            # Check for timeout error and display a more helpful message
            if "timed out" in error_msg.lower():
                print(f"⏱️ LLM request timed out after {self.timeout} seconds.")
                print(f"   Try increasing the timeout with the --timeout option or in interactive mode.")
                print(f"   Current timeout: {self.timeout} seconds")
            # Check for the case where we only got thinking content
            elif "thinking content but no action or query blocks" in error_msg:
                print(f"⚠️ The LLM generated thinking content but no action or query code blocks.")
                print(f"   This can happen with some models, especially with smaller context windows.")
                print(f"   Try the following solutions:")
                print(f"   1. Use a different model with better instruction following")
                print(f"   2. Try a simpler scenario description")
                print(f"   3. If using an HTTP API, check if the API is properly configured")
                
                # Show the thinking content to help the user understand what the model was trying to do
                thinking = llm_result.get("thinking", [])
                if thinking:
                    print(f"\n💭 The model was thinking:")
                    for i, thought in enumerate(thinking[:3], 1):  # Show first 3 thoughts only
                        short_thought = thought[:150] + "..." if len(thought) > 150 else thought
                        print(f"  {i}. {short_thought}")
                    if len(thinking) > 3:
                        print(f"     ... ({len(thinking) - 3} more thinking blocks)")
            else:
                print(f"❌ LLM query failed: {error_msg}")
                
                # Display any available debug info
                if "debug_info" in llm_result:
                    print(f"   Debug info: {llm_result['debug_info']}")
                
            return llm_result
        
        # Get thinking process if available
        thinking = llm_result.get("thinking", [])
        if thinking:
            print(f"💭 LLM thinking process:")
            for thought in thinking:
                print(f"  • {thought}")
        
        # Handle query or action
        response_type = llm_result.get("response_type")
        
        # Log if function signatures were fixed
        if llm_result.get("fixed_signature", False):
            print("ℹ️ Fixed invalid function signature in LLM response")
        
        if response_type == "query":
            print(f"🔍 LLM is querying environment")
            query_code = llm_result.get("query_code", "")
            
            # Debug: Check if the query code is valid
            if not query_code or "def query" not in query_code:
                print(f"❌ Invalid query code format")
                if query_code:
                    print(f"   Received code snippet: {query_code[:100]}...")
                return {
                    "success": False,
                    "error": "Invalid query code format",
                    "response_type": "query"
                }
                
            try:
                # IMPORTANT: This is unsafe in production as it allows arbitrary code execution
                # A safer approach would be to parse the query and use predefined API methods
                
                # Create a local function from the query code
                local_vars = {
                    "environment_state_service": self.environment_state,
                    "attack_graph_service": self.attack_graph
                }
                
                # Pass the required environment variables in globals to make them accessible
                global_vars = {
                    "environment_state_service": self.environment_state,
                    "attack_graph_service": self.attack_graph
                }
                
                exec(query_code, global_vars, local_vars)
                query_result = local_vars.get("query")()
                
                # Save the query result for future reference
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"{self.output_dir}/query_{timestamp}.json"
                with open(output_file, 'w') as f:
                    # Handle complex objects that might not be JSON serializable
                    try:
                        json.dump(query_result, f, indent=2, default=str)
                    except:
                        with open(output_file, 'w') as f:
                            f.write(str(query_result))
                
                return {
                    "success": True,
                    "response_type": "query",
                    "query_result": query_result,
                    "query_file": output_file
                }
            
            except Exception as e:
                print(f"❌ Error executing query: {e}")
                print(f"   Query code: {query_code}")
                return {
                    "success": False,
                    "error": f"Query execution error: {str(e)}",
                    "response_type": "query"
                }
        
        elif response_type == "action":
            print(f"🚀 LLM is executing action")
            action_code = llm_result.get("action_code", "")
            
            # Debug: Check if the action code is valid
            if not action_code or "def action" not in action_code:
                print(f"❌ Invalid action code format")
                if action_code:
                    print(f"   Received code snippet: {action_code[:100]}...")
                return {
                    "success": False,
                    "error": "Invalid action code format",
                    "response_type": "action"
                }
                
            # Check for unsupported action types
            if any(unsupported in action_code for unsupported in ["VulnerabilityScanAction", "ExploitAction", "PrivilegeEscalationAction"]):
                print(f"❌ LLM tried to use an unsupported action type")
                print(f"   Only ScanNetworkAction and TestCredentialsAction are currently supported")
                print(f"   Action code: {action_code}")
                return {
                    "success": False,
                    "error": "Unsupported action type requested",
                    "response_type": "action",
                    "suggestion": "Try a different scenario description that leads to network scanning or credential testing actions"
                }
                
            try:
                # IMPORTANT: This is unsafe in production as it allows arbitrary code execution
                # A safer approach would be to parse the action and use predefined API methods
                
                # Create a local function from the action code
                local_vars = {
                    "ScanNetworkAction": ScanNetworkAction,
                    "TestCredentialsAction": TestCredentialsAction,
                    "environment_state_service": self.environment_state,
                    "attack_graph_service": self.attack_graph
                }
                
                # Pass the required names in globals to make them available in the function execution scope
                global_vars = {
                    "ScanNetworkAction": ScanNetworkAction,
                    "TestCredentialsAction": TestCredentialsAction
                }
                
                exec(action_code, global_vars, local_vars)
                action_result = local_vars.get("action")()
                
                # Validate that all actions are of supported types
                for action in action_result:
                    if not isinstance(action, (ScanNetworkAction, TestCredentialsAction)):
                        print(f"❌ LLM returned an unsupported action type: {type(action).__name__}")
                        print(f"   Only ScanNetworkAction and TestCredentialsAction are currently supported")
                        return {
                            "success": False,
                            "error": f"Unsupported action type: {type(action).__name__}",
                            "response_type": "action"
                        }
                
                # Execute the action(s)
                execution_results = []
                for action in action_result:
                    result = self.action_planner.execute_action(action)
                    execution_results.append(result)
                
                return {
                    "success": True,
                    "response_type": "action",
                    "execution_results": execution_results
                }
            
            except Exception as e:
                print(f"❌ Error executing action: {e}")
                print(f"   Action code: {action_code}")
                return {
                    "success": False,
                    "error": f"Action execution error: {str(e)}",
                    "response_type": "action"
                }
        
        else:
            print(f"❌ LLM response type not recognized: {response_type}")
            return {
                "success": False,
                "error": "Unrecognized response type",
                "raw_response": llm_result.get("raw_response", "")
            }
    
    def interactive_mode(self):
        """Interactive CLI mode for SmirkingFace"""
        print("\n😏😏 SmirkingFace Interactive Mode 😏😏\n")
        
        while True:
            print("\n" + "="*60)
            print("SmirkingFace Commands:")
            print("  1. Scan target")
            print("  2. Test credentials")
            print("  3. View environment state")
            print("  4. Analyze attack paths")
            print("  5. Identify critical hosts")
            print("  6. Get suggested actions")
            print("  7. AI mode (LLM-guided)")
            print("  0. Exit")
            print("="*60)
            
            choice = input("\nEnter command number: ").strip()
            
            if choice == "0":
                print("Exiting SmirkingFace...")
                break
            
            if choice == "1":
                target = input("Enter target IP or hostname: ").strip()
                scan_type = input("Enter scan type (full/quick/service) [full]: ").strip() or "full"
                self.scan_target(target, scan_type)
            
            elif choice == "2":
                target = input("Enter target IP or hostname: ").strip()
                service = input("Enter service (ssh/ftp/http/https): ").strip()
                use_common = input("Use common credentials? (y/n) [y]: ").strip().lower() != "n"
                username = input("Enter username (optional): ").strip() or None
                password = input("Enter password (optional): ").strip() or None
                self.test_target_credentials(target, service, username, password, use_common)
            
            elif choice == "3":
                hosts = self.environment_state.network.get_all_hosts()
                print(f"\nEnvironment State: {len(hosts)} hosts")
                
                for host in hosts:
                    print(f"\n🖥️  Host: {host.ip_address} ({host.hostname})")
                    print(f"   Access Level: {host.access_level}")
                    
                    print(f"   Services:")
                    for name, info in host.services.items():
                        print(f"     - {name} (Port {info.get('port')}): {info.get('version', 'Unknown')}")
                    
                    print(f"   Vulnerabilities:")
                    if host.vulnerabilities:
                        for vuln in host.vulnerabilities:
                            print(f"     - {vuln.get('name')} (Severity: {vuln.get('severity')})")
                    else:
                        print("     - None detected")
            
            elif choice == "4":
                target = input("Enter target IP: ").strip()
                self.get_attack_paths(target)
            
            elif choice == "5":
                self.get_critical_hosts()
            
            elif choice == "6":
                target = input("Enter target IP (leave empty for global suggestions): ").strip() or None
                self.get_next_actions(target)
            
            elif choice == "7":
                if not self.llm.model_path or not self.llm.api_base:
                    model_path = input("Enter path to local model or API identifier: ").strip()
                    api_type = input("Enter API type (local/openai/http) [local]: ").strip() or "local"
                    api_base = None
                    if api_type == "http":
                        api_base = input("Enter API base URL [http://localhost:5000/v1]: ").strip() or "http://localhost:5000/v1"
                    
                    # Ask for timeout configuration
                    timeout_input = input(f"Enter timeout in seconds [current: {self.timeout}]: ").strip()
                    if timeout_input and timeout_input.isdigit():
                        self.timeout = int(timeout_input)
                        print(f"⏱️ Timeout set to {self.timeout} seconds")
                    
                    self.llm = LLMIntegration(model_path, api_type, api_base, timeout=self.timeout)
                else:
                    # Option to update just the timeout
                    update_timeout = input("Update LLM timeout? (y/n) [n]: ").strip().lower() == "y"
                    if update_timeout:
                        timeout_input = input(f"Enter timeout in seconds [current: {self.timeout}]: ").strip()
                        if timeout_input and timeout_input.isdigit():
                            self.timeout = int(timeout_input)
                            # Recreate LLM integration with new timeout
                            self.llm = LLMIntegration(self.llm.model_path, self.llm.api_type, self.llm.api_base, timeout=self.timeout)
                            print(f"⏱️ Timeout set to {self.timeout} seconds")
                
                scenario = input("Enter scenario description: ").strip() or "Perform security assessment"
                self.process_llm_action(scenario)
            
            else:
                print("Invalid command")
            
            # Pause to let user read output
            input("\nPress Enter to continue...")
    
    def run(self, target: str = None, scan_type: str = "full", ai_mode: bool = False, scenario: str = None):
        """
        Run SmirkingFace in automated mode.
        
        Args:
            target: Target IP or hostname
            scan_type: Type of scan to perform
            ai_mode: Whether to use LLM for decision making
            scenario: Scenario description for AI mode
        """
        if self.interactive:
            self.interactive_mode()
            return
        
        # Non-interactive mode
        if target:
            print(f"🔍 Automated mode for target: {target}")
            
            # Initial scan
            scan_result = self.scan_target(target, scan_type)
            
            if not scan_result["success"]:
                print("❌ Initial scan failed, exiting")
                return
            
            # Get suggested actions
            suggestions = self.get_next_actions(target)
            
            # If AI mode enabled, use LLM for decision making
            if ai_mode:
                current_scenario = scenario or f"Perform security assessment on {target}"
                print(f"🧠 Activating AI mode with scenario: {current_scenario}")
                
                for i in range(3):  # Limit to 3 AI-guided actions
                    action_result = self.process_llm_action(current_scenario)
                    if not action_result["success"]:
                        print(f"❌ AI-guided action {i+1} failed, stopping")
                        break
                    
                    print(f"✅ AI-guided action {i+1} completed")
                    time.sleep(2)  # Brief pause between actions
            
            # Get attack paths as final step
            self.get_attack_paths(target)
        
        else:
            print("❌ No target specified for automated mode")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="SmirkingFace - LLM-powered penetration testing tool")
    parser.add_argument("-t", "--target", help="Target IP or hostname")
    parser.add_argument("-s", "--scan-type", default="full", choices=["full", "quick", "service"], help="Scan type")
    parser.add_argument("-d", "--data-dir", default="data", help="Data directory")
    parser.add_argument("-o", "--output-dir", default="output", help="Output directory")
    parser.add_argument("-i", "--interactive", action="store_true", help="Interactive mode")
    parser.add_argument("-a", "--ai-mode", action="store_true", help="AI-guided mode")
    parser.add_argument("-m", "--model-path", help="Path to local model or API identifier")
    parser.add_argument("-p", "--api-type", default="local", choices=["local", "openai", "http"], help="API type for LLM")
    parser.add_argument("-b", "--api-base", help="Base URL for HTTP API (e.g., http://localhost:5000/v1)")
    parser.add_argument("--scenario", help="Scenario description for AI mode")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout in seconds for LLM requests (default: 300)")
    
    args = parser.parse_args()
    
    # Initialize SmirkingFace
    sf = SmirkingFace(
        model_path=args.model_path,
        api_type=args.api_type,
        api_base=args.api_base,
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        interactive=args.interactive,
        timeout=args.timeout
    )
    
    # Run in appropriate mode
    sf.run(
        target=args.target,
        scan_type=args.scan_type,
        ai_mode=args.ai_mode,
        scenario=args.scenario
    )

if __name__ == "__main__":
    main() 