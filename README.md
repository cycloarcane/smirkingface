# 😏 SmirkingFace 😏

Welcome to **SmirkingFace**, an LLM-powered penetration testing framework that combines network scanning, attack path analysis, and critical host identification to enhance security posture assessment.

## 🚨 Disclaimer

This tool is **intended for responsible and lawful use only**. Users are solely accountable for their activities and compliance with applicable laws and terms of service (ToS). Misuse or illegal usage may violate platform ToS or legal standards.

## 📜 Project Summary

**SmirkingFace** is a comprehensive penetration testing framework that leverages advanced Language Models (LLMs) to:

1. **Scan Networks**: Perform detailed network scans to discover hosts, services, and vulnerabilities
2. **Analyze Attack Paths**: Identify potential attack vectors between hosts in a network
3. **Identify Critical Hosts**: Determine which hosts are most strategically important in a network
4. **Simulate Environments**: Generate realistic network environments for testing and demonstration
5. **AI-Guided Testing**: Use LLMs to suggest and execute penetration testing actions

The framework implements a structured approach with these key components:

- **Environment State Service**: Maintains state of discovered hosts, services, vulnerabilities, and credentials
- **Attack Graph Service**: Models potential attack paths between hosts using graph theory
- **Action Planner**: Translates high-level tasks into specific commands and executes them
- **LLM Integration**: Handles communication with local or API-based LLM models
- **Simulation Environment**: Generates realistic network environments for testing

## 🌐 Repository and Contact

- **GitHub**: [SmirkingFace](https://github.com/cycloarcane/smirkingface)
- **Email**: [cycloarkane@gmail.com](mailto:cycloarkane@gmail.com)

## 📥 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/cycloarcane/smirkingface.git
   cd smirkingface
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install external tools:

   ### Arch Linux
   ```bash
   # Install Nmap
   sudo pacman -S nmap
   
   # Install Exploitdb (for searchsploit)
   sudo pacman -S exploitdb
   ```

   ### Debian/Ubuntu
   ```bash
   # Install Nmap
   sudo apt-get update
   sudo apt-get install nmap
   
   # Install Exploitdb (for searchsploit)
   sudo apt-get install exploitdb
   ```

   ### macOS
   ```bash
   # Install Homebrew if not already installed
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   
   # Install Nmap
   brew install nmap
   
   # Install Exploitdb (for searchsploit)
   brew install exploitdb
   ```

4. Create data directories:
   ```bash
   mkdir -p data output
   ```

5. Make the scripts executable:
   ```bash
   chmod +x smirkingface.py simulation.py
   ```

## 🚀 Usage

### Command Line Interface

SmirkingFace can be operated in interactive or automated mode:

```bash
# Interactive mode
python smirkingface.py -i

# Scan a specific target
python smirkingface.py -t 192.168.1.1 -s full

# Use AI-guided mode with a specific model
python smirkingface.py -t 192.168.1.1 -a -m /path/to/local/model.bin
```

### Simulation Environment

SmirkingFace includes a simulation environment for testing and demonstration:

```bash
# Run with default simple network (2 hosts)
python simulation.py

# Run with complex network (10 hosts by default)
python simulation.py -c complex

# Run with custom number of hosts
python simulation.py -c complex -n 15

# Use custom data directories
python simulation.py -c complex -d custom_data -o custom_output
```

### Command Line Options

```
-t, --target        Target IP or hostname
-s, --scan-type     Scan type (full/quick/service)
-d, --data-dir      Data directory for storing state (default: data)
-o, --output-dir    Output directory for results (default: output)
-i, --interactive   Run in interactive mode
-a, --ai-mode       Use AI to guide decisions
-m, --model-path    Path to local model or API identifier
-p, --api-type      LLM API type (local/openai/http)
-b, --api-base      Base URL for HTTP API (e.g., http://localhost:5000/v1)
--scenario          Scenario description for AI mode
--timeout           Timeout in seconds for LLM requests (default: 300)
```

### Interactive Mode Commands

In interactive mode, you can perform the following actions:

1. **Scan Target**: Performs network scanning on a target
2. **Test Credentials**: Tests credentials on a specific service
3. **View Environment State**: Shows the current state of discovered hosts
4. **Analyze Attack Paths**: Finds potential attack paths to a target
5. **Identify Critical Hosts**: Identifies critical hosts in the environment
6. **Get Suggested Actions**: Gets suggested next actions
7. **AI Mode**: Uses LLM to determine and execute actions

## 🧠 Key Features

### Attack Path Analysis

SmirkingFace can analyze potential attack paths between hosts in a network:

- Identifies possible attack vectors based on vulnerabilities and network topology
- Calculates probability of success and impact for each attack path
- Ranks attack paths by effectiveness and efficiency
- Visualizes attack paths for better understanding

### Critical Host Identification

The framework can identify critical hosts in a network:

- Analyzes network topology to find central nodes
- Evaluates host importance based on services and vulnerabilities
- Ranks hosts by strategic importance
- Helps focus penetration testing efforts on high-value targets

### Simulation Environment

The simulation environment creates realistic network scenarios:

- Generates hosts with appropriate services and vulnerabilities
- Creates network segments (DMZ, web, app, db, internal)
- Adds simulated credentials and compromised hosts
- Records scan history to simulate previous reconnaissance

### LLM Integration

SmirkingFace supports multiple ways to integrate with LLMs:

#### Local Models (Binary)

For local binary models like llama.cpp:

```bash
# Example with a local llama.cpp model
python smirkingface.py -i -p local -m /path/to/llama.cpp

# Example with increased timeout for slow models (10 minutes)
python smirkingface.py -i -p local -m /path/to/llama.cpp --timeout 600
```

#### HTTP API (Local Server)

For local models running behind HTTP APIs (like LM Studio, llama.cpp server, etc.):

```bash
# Example with a model running at http://localhost:5000/v1
python smirkingface.py -i -p http -b http://localhost:5000/v1
```

#### API-Based Models (OpenAI)

You can also use OpenAI's API:

```bash
# Export your API key
export OPENAI_API_KEY=your_api_key_here

# Run with OpenAI API
python smirkingface.py -i -p openai -m gpt-3.5-turbo
```

### LLM Timeout Configuration

SmirkingFace provides flexible timeout settings for LLM requests:

- Default timeout: 300 seconds (5 minutes)
- Command line: Use `--timeout` to set a custom timeout in seconds
- Interactive mode: When selecting AI mode (option 7), you can update the timeout
- For large local models: Consider using timeouts of 600-900 seconds (10-15 minutes)

## 📋 Framework Components

### Environment State Service

- Tracks discovered hosts, their services, vulnerabilities, and credentials
- Persists state between runs
- Provides an API for querying environment state
- Manages host access levels (none, user, admin, system)

### Attack Graph Service

- Builds attack graphs based on discovered vulnerabilities and network topology
- Finds potential attack paths between hosts using graph algorithms
- Identifies critical hosts in the environment
- Calculates probability and impact metrics for attack paths

### Action Planner

- Translates high-level tasks into specific actions
- Executes actions and updates environment state
- Suggests potential next actions based on current state
- Handles network scanning and credential testing

### LLM Integration

- Handles communication with local and API-based models
- Formats prompts for structured outputs
- Manages timeouts and error handling
- Extracts and processes model responses

## 📧 Contact

For any inquiries or collaboration, reach out at cycloarkane@gmail.com.

---

#### License

This project is licensed under a modified license with the [Commons Clause](https://commonsclause.com/), restricting commercial usage.
