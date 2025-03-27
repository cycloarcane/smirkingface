# 😏😏 SmirkingFace 😏😏

Welcome to **SmirkingFace**, an LLM-powered penetration testing tool designed to uncover security vulnerabilities and enhance the security posture and compliance of individuals and organizations.

## 🚨 Disclaimer

This tool is **intended for responsible and lawful use only**. Users are solely accountable for their activities and compliance with applicable laws and terms of service (ToS). Misuse or illegal usage may violate platform ToS or legal standards.

## 📜 Project Summary

**SmirkingFace** leverages advanced Language Models (LLMs) to perform comprehensive penetration testing in a multi-step process:

1. **Initial Scanning**: Runs initial scans on a target to gather information and build a detailed security profile.
2. **Credential Testing**: Attempts login using common or known credentials based on scan results.
3. **Exploit Execution**: Downloads, modifies, and executes proof-of-concept exploit code tailored to the target system.

The project implements a structured approach inspired by the Incalmo framework to improve LLM effectiveness in cybersecurity tasks:

- **Environment State Service**: Maintains state of discovered hosts, services, and vulnerabilities
- **Attack Graph Service**: Models potential attack paths between hosts
- **Action Planner**: Translates high-level tasks into specific commands
- **LLM Integration**: Handles communication with local LLM models, stripping `<think>` tags

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

5. Make the main script executable:
   ```bash
   chmod +x smirkingface.py
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

## 🧠 LLM Integration

SmirkingFace supports multiple ways to integrate with LLMs:

### Local Models (Binary)

For local binary models like llama.cpp:

```bash
# Example with a local llama.cpp model
python smirkingface.py -i -p local -m /path/to/llama.cpp

# Example with increased timeout for slow models (10 minutes)
python smirkingface.py -i -p local -m /path/to/llama.cpp --timeout 600
```

### HTTP API (Local Server)

For local models running behind HTTP APIs (like LM Studio, llama.cpp server, etc.):

```bash
# Example with a model running at http://localhost:5000/v1
python smirkingface.py -i -p http -b http://localhost:5000/v1

# Example with increased timeout for large local reasoning models
python smirkingface.py -i -p http -b http://localhost:5000/v1 --timeout 600
```

You can also set this up through the interactive mode by selecting option 7 (AI mode) and then:
- API type: `http`
- API base URL: `http://localhost:5000/v1`
- Timeout: You'll be prompted to set a timeout (in seconds)

This option is perfect for models running in LM Studio, llama.cpp server, or any OpenAI-compatible API.

### API-Based Models (OpenAI)

You can also use OpenAI's API:

```bash
# Export your API key
export OPENAI_API_KEY=your_api_key_here

# Run with OpenAI API
python smirkingface.py -i -p openai -m gpt-3.5-turbo
```

### Handling `<think>` Tags

SmirkingFace automatically handles `<think>` tags from local models. Instead of removing these via prompting, the framework:

1. Extracts content inside `<think>` tags
2. Stores this content for analysis
3. Removes the tags from the response shown to the user

This approach preserves the quality benefits of local models while maintaining clean output.

### LLM Timeout Configuration

SmirkingFace provides flexible timeout settings for LLM requests, which is particularly useful for local reasoning models that may take longer to generate responses:

- Default timeout: 300 seconds (5 minutes)
- Command line: Use `--timeout` to set a custom timeout in seconds
- Interactive mode: When selecting AI mode (option 7), you can update the timeout
- For large local models: Consider using timeouts of 600-900 seconds (10-15 minutes)

The timeout applies to all LLM communication methods (local binary, HTTP API, and OpenAI).

## 📋 Framework Components

### Environment State Service

- Tracks discovered hosts, their services, and vulnerabilities
- Persists state between runs
- Provides an API for querying environment state

### Attack Graph Service

- Builds attack graphs based on discovered vulnerabilities
- Finds potential attack paths between hosts
- Identifies critical hosts in the environment

### Action Planner

- Translates high-level tasks into specific actions
- Executes actions and updates environment state
- Suggests potential next actions

### LLM Integration

- Handles communication with local and API-based models
- Strips `<think>` tags from responses
- Formats prompts for structured outputs

## 📧 Contact

For any inquiries or collaboration, reach out at cycloarkane@gmail.com.

---

#### License

This project is licensed under a modified license with the [Commons Clause](https://commonsclause.com/), restricting commercial usage.
