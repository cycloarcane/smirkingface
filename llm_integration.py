import os
import re
import json
import subprocess
from typing import Dict, List, Any, Optional, Union, Callable
import requests

class LLMIntegration:
    """Class to handle communication with local LLMs, including handling <think> tags."""
    
    def __init__(self, model_path: str = None, api_type: str = "local", api_base: str = None):
        """
        Initialize LLM integration.
        
        Args:
            model_path: Path to local model or API identifier
            api_type: Type of API to use - "local", "openai", "llamacpp", "http", etc.
            api_base: Base URL for HTTP API (e.g., "http://localhost:5000/v1")
        """
        self.model_path = model_path
        self.api_type = api_type
        self.api_base = api_base
        self.think_pattern = re.compile(r'<think>(.*?)</think>', re.DOTALL)
        self.thinking_history = []
    
    def query(self, prompt: str, system_prompt: str = None, 
              temperature: float = 0.7, max_tokens: int = 2048) -> Dict:
        """
        Query the LLM with given prompt.
        
        Args:
            prompt: User query prompt
            system_prompt: Optional system prompt to guide the model
            temperature: Sampling temperature (0.0 to 1.0)
            max_tokens: Maximum number of tokens to generate
            
        Returns:
            Dictionary with response text and metadata
        """
        if self.api_type == "local":
            return self._query_local(prompt, system_prompt, temperature, max_tokens)
        elif self.api_type == "openai":
            return self._query_openai(prompt, system_prompt, temperature, max_tokens)
        elif self.api_type == "http":
            return self._query_http_api(prompt, system_prompt, temperature, max_tokens)
        else:
            raise ValueError(f"Unsupported API type: {self.api_type}")
    
    def _query_local(self, prompt: str, system_prompt: str = None, 
                    temperature: float = 0.7, max_tokens: int = 2048) -> Dict:
        """Query a local LLM using subprocess."""
        # Build command for local model
        if not self.model_path:
            raise ValueError("Model path not specified for local LLM")
        
        # Example command for llama.cpp
        cmd = [
            self.model_path,
            "--temp", str(temperature),
            "--n-predict", str(max_tokens)
        ]
        
        # Add system prompt if provided
        full_prompt = ""
        if system_prompt:
            full_prompt = f"<s>[INST] <<SYS>>\n{system_prompt}\n<</SYS>>\n\n"
        
        # Add user prompt
        full_prompt += f"{prompt} [/INST]"
        
        try:
            # Run the command
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Send prompt and get response
            stdout, stderr = process.communicate(input=full_prompt)
            
            if process.returncode != 0:
                return {
                    "success": False,
                    "error": f"LLM process exited with code {process.returncode}: {stderr}",
                    "raw_response": stderr
                }
            
            # Process the response
            return self._process_response(stdout)
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "raw_response": None
            }
    
    def _query_openai(self, prompt: str, system_prompt: str = None, 
                     temperature: float = 0.7, max_tokens: int = 2048) -> Dict:
        """Query OpenAI compatible API."""
        try:
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {os.environ.get('OPENAI_API_KEY')}"
            }
            
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            
            messages.append({"role": "user", "content": prompt})
            
            data = {
                "model": self.model_path or "gpt-3.5-turbo",
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens
            }
            
            response = requests.post(
                "https://api.openai.com/v1/chat/completions",
                headers=headers,
                json=data
            )
            
            if response.status_code != 200:
                return {
                    "success": False,
                    "error": f"API error: {response.status_code} {response.text}",
                    "raw_response": response.text
                }
            
            result = response.json()
            assistant_response = result["choices"][0]["message"]["content"]
            
            return self._process_response(assistant_response)
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "raw_response": None
            }
    
    def _query_http_api(self, prompt: str, system_prompt: str = None, 
                       temperature: float = 0.7, max_tokens: int = 2048) -> Dict:
        """Query HTTP API endpoint (compatible with OpenAI API format)."""
        try:
            if not self.api_base:
                raise ValueError("API base URL not specified")
            
            headers = {
                "Content-Type": "application/json"
            }
            
            # Check if api_key is in environment
            api_key = os.environ.get('LLM_API_KEY')
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            
            messages.append({"role": "user", "content": prompt})
            
            data = {
                "model": self.model_path or "local-model",
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens
            }
            
            # Construct the URL for chat completions
            api_url = f"{self.api_base.rstrip('/')}/chat/completions"
            
            response = requests.post(
                api_url,
                headers=headers,
                json=data,
                timeout=60  # Longer timeout for local models
            )
            
            if response.status_code != 200:
                return {
                    "success": False,
                    "error": f"API error: {response.status_code} {response.text}",
                    "raw_response": response.text
                }
            
            result = response.json()
            assistant_response = result["choices"][0]["message"]["content"]
            
            return self._process_response(assistant_response)
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "raw_response": None
            }
    
    def _process_response(self, response: str) -> Dict:
        """
        Process LLM response, including extraction of thinking process.
        
        Args:
            response: Raw response from LLM
            
        Returns:
            Dictionary with processed response and extracted thinking
        """
        # Extract thinking from <think> tags
        thinking = []
        
        def extract_thinking(match):
            thinking.append(match.group(1).strip())
            return ""  # Remove the thinking from the response
        
        # Remove <think> tags and extract content
        clean_response = self.think_pattern.sub(extract_thinking, response)
        
        # Store thinking in history
        if thinking:
            self.thinking_history.append({
                "timestamp": os.popen("date +%s").read().strip(),
                "thinking": thinking
            })
        
        return {
            "success": True,
            "response": clean_response.strip(),
            "thinking": thinking,
            "raw_response": response
        }
    
    def get_thinking_history(self) -> List[Dict]:
        """Get the history of thinking processes."""
        return self.thinking_history
    
    def query_for_action(self, scenario: str, environment_state: Dict,
                        system_prompt: str = None) -> Dict:
        """
        Special query mode to get LLM to produce structured action plans.
        
        Args:
            scenario: Description of current scenario and goal
            environment_state: Current state of the environment
            system_prompt: Optional system prompt
            
        Returns:
            Dictionary with action plan and metadata
        """
        # Create a specialized prompt for the action planner
        action_prompt = f"""
You are an autonomous security testing agent. Based on the current environment state,
determine the next action to take to advance the security assessment.

Your response must be formatted as Python functions inside specific tags:

For queries about the environment, use:
<query>
def query(...):
    # Python code to get information from environment
    return environment_state_service.network.get_all_hosts()
</query>

For actions to execute, use:
<action>
def action(...):
    # Python code defining the action to take
    return [ScanNetworkAction(target="192.168.1.1", scan_type="full")]
</action>

Current scenario:
{scenario}

Current environment state:
{json.dumps(environment_state, indent=2)}

Respond ONLY with <query> or <action> tags containing valid Python code.
"""
        
        if not system_prompt:
            system_prompt = """
You are SmirkingFace, an advanced penetration testing assistant.
Your goal is to help identify and test security vulnerabilities through a structured, methodical approach.

Please always think step by step, planning your actions carefully.
First analyze the current state, then decide on the most effective next action.

Always follow security testing best practices and prioritize actions based on:
1. Information gathering
2. Service enumeration
3. Vulnerability detection
4. Credential testing
5. Exploitation
6. Privilege escalation
7. Lateral movement

Format your responses precisely as requested using the specified tags.
"""

        # Get response from LLM
        response = self.query(action_prompt, system_prompt)
        
        # Extract action or query from response
        action_match = re.search(r'<action>(.*?)</action>', response.get("response", ""), re.DOTALL)
        query_match = re.search(r'<query>(.*?)</query>', response.get("response", ""), re.DOTALL)
        
        result = {
            "success": response.get("success", False),
            "raw_response": response.get("raw_response", ""),
            "thinking": response.get("thinking", [])
        }
        
        if action_match:
            result["action_code"] = action_match.group(1).strip()
            result["response_type"] = "action"
        elif query_match:
            result["query_code"] = query_match.group(1).strip()
            result["response_type"] = "query"
        else:
            result["success"] = False
            result["error"] = "No valid action or query found in response"
            
        return result
    
    def format_environment_for_llm(self, environment_state_service) -> Dict:
        """
        Format environment state in a way that's useful for the LLM.
        
        Args:
            environment_state_service: EnvironmentStateService instance
            
        Returns:
            Simplified dictionary with relevant environment state
        """
        # Get the network state
        network = environment_state_service.network
        
        # Simplify host data for better LLM understanding
        hosts_data = []
        for host in network.get_all_hosts():
            # Get key vulnerability information
            vulns = []
            for v in host.vulnerabilities:
                vulns.append({
                    "id": v.get("id", "unknown"),
                    "name": v.get("name", "Unknown"),
                    "severity": v.get("severity", "Unknown"),
                    "service": v.get("service", "")
                })
            
            # Simplified services dict
            services = {}
            for name, info in host.services.items():
                services[name] = {
                    "port": info.get("port", 0),
                    "version": info.get("version", "Unknown")
                }
            
            # Add simplified host data
            hosts_data.append({
                "ip": host.ip_address,
                "hostname": host.hostname,
                "access_level": host.access_level,
                "services": services,
                "open_ports": list(host.open_ports.keys()),
                "vulnerabilities": vulns
            })
        
        # Format into simple environment state dictionary
        env_state = {
            "hosts": hosts_data,
            "total_host_count": len(hosts_data),
            "scan_history_count": len(network.scan_history)
        }
        
        return env_state 