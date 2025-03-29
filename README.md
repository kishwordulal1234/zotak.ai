# ZOTAK - AI-Powered Pentesting CLI

<p align="center">
  <img src="https://raw.githubusercontent.com/username/zotak/main/images/logo.png" alt="Zotak Logo" width="400"/>
</p>

<p align="center">
  <em>Revolutionize penetration testing with AI-driven command generation and analysis</em>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#requirements">Requirements</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#usage">Usage</a> •
  <a href="#examples">Examples</a> •
  <a href="#ethical-use">Ethical Use</a> •
  <a href="#license">License</a>
</p>

---

## Overview

Zotak is an advanced AI-powered CLI tool designed to streamline and enhance penetration testing workflows. It leverages state-of-the-art large language models to interpret natural language commands, generate appropriate pentesting commands, analyze results, and suggest exploitation paths - all from a sleek, interactive terminal interface.

Unlike traditional pentesting frameworks that require memorization of specific commands and syntax, Zotak accepts natural language instructions and translates them into powerful Kali Linux commands, making advanced security testing accessible to both experts and newcomers.

## Features

- **Natural Language Processing**: Input commands in plain English and let the AI figure out the technical details
- **Multi-AI Provider Support**: Choose between OpenRouter (DeepSeek) and Google Gemini AI models
- **Automatic Tool Installation**: Detects and installs missing tools automatically
- **Enhanced Reconnaissance**: Comprehensive recon with multiple fallback mechanisms
- **Intelligent Analysis**: Automatically identifies interesting findings in scan results
- **Exploitation Suggestions**: Receives AI-generated exploitation suggestions based on scan results
- **Result Management**: Organized storage and viewing of scan results
- **Custom Prompt Styles**: Multiple interactive CLI styles to choose from
- **Real-time Target Analysis**: Receive immediate intelligence about target domains
- **Failsafe Mechanisms**: Timeout handling, graceful interruptions, and confirmation for risky commands

## Installation

```bash
# Clone the repository
git clone https://github.com/username/zotak.git
cd zotak

# Install requirements
pip install -r requirements.txt

# Make the script executable
chmod +x zotak.py

# Run the tool
./zotak.py
```

## Requirements

### Python Dependencies
- Python 3.8+
- openai
- colorama
- requests
- google-generativeai (optional, for Gemini integration)

### System Requirements
- Kali Linux (recommended) or any Linux distribution with pentesting tools
- API keys:
  - OpenRouter API key (default included)
  - Google Gemini API key (optional)

### Recommended Tools
The following tools improve Zotak's capabilities but are not strictly required as Zotak will attempt to install them when needed:

- nmap
- gobuster
- dirb
- dirsearch
- ffuf
- sqlmap
- nikto
- whatweb
- hydra
- metasploit-framework

## Quick Start

```bash
# Start Zotak
python3 zotak.py

# Set a target
set target example.com

# Run basic reconnaissance
recon

# Check for specific vulnerabilities
check for sql injection vulnerabilities

# Show scan results
show scan
```

## Usage

### Basic Commands

| Command | Description |
|---------|-------------|
| `set target [hostname/IP]` | Set target for testing |
| `recon` | Run comprehensive reconnaissance |
| `fast recon` | Run quick reconnaissance |
| `improve it` | Generate improved version of the last command |
| `show scan` | List recent scan results |
| `show scan [number/name]` | View specific scan result |
| `change prompt` | Cycle through different prompt styles |
| `use openrouter` | Switch to OpenRouter API |
| `use gemini` | Switch to Google Gemini API (if available) |
| `show provider` | Show current AI provider |
| `stop` | Stop all running scans |
| `exit` | Exit the application |

### Natural Language Commands

Simply type what you want to do in natural language, and the AI will generate and execute the appropriate commands:

```bash
# Examples of natural language commands
scan target for open ports
check for sql injection vulnerabilities
search for wordpress vulnerabilities
perform directory brute force with common wordlist
run nikto scan on the target
generate reverse shell payload for windows 
```

### Setting Targets

```bash
# Set a target domain
set target example.com

# Set a target with URL (http:// will be stripped)
set target https://example.com/

# Set an IP address
set target 192.168.1.1
```

### Running Scans

```bash
# Comprehensive reconnaissance (nmap, whatweb, directory enumeration)
recon

# Quick scan
fast recon

# Custom scan with natural language
scan for SQL injection in the login form
```

### Viewing Results

```bash
# List all recent scan results
show scan

# View a specific scan by number
show scan 1

# View a specific scan by filename pattern
show scan nmap

# View a specific file directly
show scan /root/zotak_results/nmap_example_com_20250329.txt
```

### Using Different AI Providers

```bash
# Use DeepSeek model via OpenRouter
use openrouter

# Use Google's Gemini model (if available)
use gemini

# Check which provider is currently active
show provider
```

## Advanced Features

### Target Analysis

When you set a target, Zotak automatically analyzes it and provides:
- Type of target (CMS, web application, etc.)
- Common vulnerabilities associated with similar targets
- Recommended reconnaissance steps

### Intelligent Scan Analysis

After running scans, Zotak:
1. Analyzes the output for interesting findings
2. Highlights important discoveries
3. Suggests potential exploitation commands

### Multi-tool Directory Brute Forcing

Zotak uses an intelligent, multi-tool approach for directory scanning:
- Automatically selects the best available tool (gobuster, dirb, dirsearch, ffuf)
- Implements sensible timeouts and rate limiting
- Falls back to alternative tools if the first choice fails

### Command Improvement

The `improve it` command enhances your previous scan:
- Adds more relevant command-line options
- Uses more thorough search parameters
- Implements recommended scanning practices

## Examples

### Example 1: Basic Reconnaissance

```bash
[H4X0R] > set target testphp.vulnweb.com
[+] Target set to: testphp.vulnweb.com
[*] Getting target information...

TARGET ANALYSIS:
This is a deliberately vulnerable web application for testing purposes.
Common vulnerabilities include SQL injection, XSS, and file inclusion.
Start with port scanning, web fingerprinting, and directory enumeration.

[H4X0R] > recon
[+] Starting enhanced reconnaissance on testphp.vulnweb.com
[*] Running comprehensive recon mode
[*] Phase 1: Port scanning with service detection
...
```

### Example 2: Finding SQL Injection

```bash
[H4X0R] > check for sql injection
[*] Processing...
[*] This command uses sqlmap to check for SQL injection vulnerabilities in the target website.
[+] Executing in your Kali terminal: sqlmap -u "http://testphp.vulnweb.com/listproducts.php?cat=1" --batch
...
[+] Interesting findings:
[!] SQL Injection found: Parameter 'cat' is vulnerable to boolean-based blind
...
```

### Example 3: Using Different AI Provider

```bash
[H4X0R] > use gemini
[+] Switched to Google Gemini API with model: gemini-2.0-flash
[H4X0R] > check for open ports
[*] Processing...
[INFO] Querying Gemini API (gemini-2.0-flash)
...
```

## Troubleshooting

### Common Issues

1. **"Error querying AI" message**
   - Check your internet connection
   - Verify API key validity
   - Try switching to a different AI provider

2. **Tool installation failures**
   - Run Zotak with sudo/root privileges
   - Update your package lists (`apt update`)
   - Install the tool manually and retry

3. **Timeouts during directory scanning**
   - Try the `fast recon` command for quicker results
   - Specify a different directory scanning tool: `dirb scan target`

4. **Commands not executing properly**
   - Check if you have the tool installed
   - Verify you have set a target if needed
   - Ensure you have network access to the target

## Ethical Use and Disclaimer

⚠️ **IMPORTANT DISCLAIMER**

Zotak is a powerful penetration testing tool developed for security professionals, researchers, and system administrators to legally test systems they own or have explicit permission to test.

**You must:**
- Only use Zotak on systems you own or have explicit permission to test
- Comply with all applicable laws and regulations
- Respect the privacy and property of others

**Illegal use of this tool may result in:**
- Criminal charges
- Civil liability
- Severe legal penalties

The developers of Zotak assume no liability and are not responsible for any misuse or damage caused by this tool.

## License

Zotak is released under the [MIT License](LICENSE).

---

<p align="center">
  Made with ❤️ by Zotak Development Team<br>
  <a href="https://github.com/username/zotak">GitHub</a> •
  <a href="https://zotak-cli.com">Website</a> •
  <a href="mailto:contact@zotak-cli.com">Contact</a>
</p> 