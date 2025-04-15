# ZOTAK - AI-Powered Pentesting CLI

<div align="center">
  <img src="logo.png" alt="Zotak Logo" width="400"/>
  
  <h3>🔐 Next-Generation Security Testing 🔐</h3>
  
  <p align="center">
    <em>Revolutionize penetration testing with AI-driven command generation and analysis<br>
    Break the system through security, not the device</em>
  </p>

  <p align="center">
    <a href="#-features">🚀 Features</a> •
    <a href="#-installation">⚡ Installation</a> •
    <a href="#-requirements">📋 Requirements</a> •
    <a href="#-quick-start">🎯 Quick Start</a> •
    <a href="#-usage">📖 Usage</a> •
    <a href="#-examples">💡 Examples</a> •
    <a href="#-ethical-use">🛡️ Ethical Use</a> •
    <a href="#-license">📜 License</a> •
    <a href="#-version-history">📅 Version History</a>
  </p>

  <hr>

  <p align="center">
    <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python Version">
    <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
    <img src="https://img.shields.io/badge/AI-Powered-purple.svg" alt="AI Powered">
    <img src="https://img.shields.io/badge/Platform-Linux-orange.svg" alt="Platform">
  </p>
</div>

## 🌟 Overview

<div align="center">
  <table>
    <tr>
      <td width="70%">
        <p><b>Zotak</b> is a revolutionary AI-powered CLI tool that transforms penetration testing workflows. By leveraging state-of-the-art large language models, it brings advanced security testing capabilities to both experts and newcomers.</p>
      </td>
      <td align="center" width="30%">
        <img src="https://img.shields.io/badge/AI-Models-blueviolet" alt="AI Models"><br>
        <small>DeepSeek & Gemini</small>
      </td>
    </tr>
  </table>
</div>

### 🎯 Key Benefits

<table align="center">
  <tr>
    <td align="center" width="33%">
      <h3>🤖</h3>
      <b>Natural Language</b>
      <p>No more memorizing complex commands</p>
    </td>
    <td align="center" width="33%">
      <h3>⚡</h3>
      <b>Intelligent Analysis</b>
      <p>Automated vulnerability detection</p>
    </td>
    <td align="center" width="33%">
      <h3>🛡️</h3>
      <b>Smart Protection</b>
      <p>Built-in safety mechanisms</p>
    </td>
  </tr>
</table>

## ✨ Features

<div class="feature-grid">
  <table align="center">
    <tr>
      <td align="center" width="33%">
        <h4>🗣️ Natural Language Processing</h4>
        <p>Input commands in plain English and let AI handle the technical details</p>
      </td>
      <td align="center" width="33%">
        <h4>🧠 Multi-AI Support</h4>
        <p>Choose between OpenRouter (DeepSeek) and Google Gemini AI models</p>
      </td>
      <td align="center" width="33%">
        <h4>🔄 Auto-Installation</h4>
        <p>Automatic detection and installation of required tools</p>
      </td>
    </tr>
    <tr>
      <td align="center">
        <h4>🔍 Enhanced Recon</h4>
        <p>Comprehensive reconnaissance with fallback mechanisms</p>
      </td>
      <td align="center">
        <h4>📊 Smart Analysis</h4>
        <p>Automatic identification of security findings</p>
      </td>
      <td align="center">
        <h4>💡 Exploitation Guidance</h4>
        <p>AI-generated exploitation suggestions</p>
      </td>
    </tr>
    <tr>
      <td align="center">
        <h4>📁 Result Management</h4>
        <p>Organized storage and viewing of scan results</p>
      </td>
      <td align="center">
        <h4>🎨 Custom Styling</h4>
        <p>Multiple interactive CLI styles</p>
      </td>
      <td align="center">
        <h4>🎯 Real-time Analysis</h4>
        <p>Immediate target intelligence</p>
      </td>
    </tr>
  </table>
</div>

### 🛡️ Advanced Security Features

<div align="center">
  <table>
    <tr>
      <td align="center">
        <h4>⚡ System Integration</h4>
        <ul align="left">
          <li>Built-in neofetch display</li>
          <li>Cross-platform compatibility</li>
          <li>Persistent configurations</li>
        </ul>
      </td>
      <td align="center">
        <h4>🔒 Safety Measures</h4>
        <ul align="left">
          <li>Automatic error detection</li>
          <li>Safe mode operations</li>
          <li>Command validation</li>
        </ul>
      </td>
      <td align="center">
        <h4>📈 Performance</h4>
        <ul align="left">
          <li>Interactive history</li>
          <li>Command suggestions</li>
          <li>Resource optimization</li>
        </ul>
      </td>
    </tr>
  </table>
</div>

## ⚡ Installation

<div align="center">
  <table>
    <tr>
      <td>
        <pre>
# Clone the repository
git clone https://github.com/username/zotak.git
cd zotak

# Install requirements
pip install -r requirements.txt

# Make the script executable
chmod +x zotak-v5.py

# Run the tool
./zotak-v5.py</pre>
      </td>
    </tr>
  </table>
</div>

## Requirements

### Python Dependencies
- Python 3.8+
- openai
- colorama
- requests
- google-generativeai (optional, for Gemini integration)
- prompt_toolkit
- rich
- psutil

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
python3 zotak-v5.py

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
[*] Starting SQL injection scan on testphp.vulnweb.com
[*] Running: sqlmap -u "http://testphp.vulnweb.com" --forms --batch --dbs
...
[+] SQL injection vulnerability found!
[+] Database: MySQL
[+] Tables discovered: 7
[+] Potential injection points: login.php, search.php
```

## Version History

<div align="center">
  <h3>💫 The Evolution of Zotak 💫</h3>
  <p><i>From simple beginnings to advanced AI-powered pentesting</i></p>
</div>

---

<h3 align="center">🚀 zotak-v5.py (Latest) 🚀</h3>
<h4 align="center"><i>The Complete Package</i></h4>

<table align="center">
  <tr>
    <td>✨ <b>Major Redesign</b></td>
    <td>Complete rewrite with modern OOP architecture</td>
  </tr>
  <tr>
    <td>🎨 <b>Beautiful Interface</b></td>
    <td>Rich text formatting and interactive prompts</td>
  </tr>
  <tr>
    <td>🔧 <b>Smart Error Handling</b></td>
    <td>Automatically detects and fixes common problems</td>
  </tr>
  <tr>
    <td>🌍 <b>Works Everywhere</b></td>
    <td>Compatible with different Linux distributions</td>
  </tr>
  <tr>
    <td>💾 <b>Keeps Your Settings</b></td>
    <td>Remembers your preferences between sessions</td>
  </tr>
  <tr>
    <td>📊 <b>System Info Display</b></td>
    <td>Shows your system details with neofetch integration</td>
  </tr>
  <tr>
    <td>🧠 <b>Multi-AI Power</b></td>
    <td>Can use both DeepSeek and Gemini simultaneously</td>
  </tr>
  <tr>
    <td>🔒 <b>Safer Usage</b></td>
    <td>Prevents accidentally running dangerous commands</td>
  </tr>
  <tr>
    <td>💡 <b>Command Suggestions</b></td>
    <td>Helps you find the right command with auto-completion</td>
  </tr>
  <tr>
    <td>⚡ <b>Memory Efficient</b></td>
    <td>Uses less system resources than previous versions</td>
  </tr>
</table>

---

<h3 align="center">💪 zotak-v4.py 💪</h3>
<h4 align="center"><i>Enhanced Intelligence</i></h4>

<p align="center">
  🤖 <b>Two Brains Are Better</b>: Added ability to use two AI models at once<br>
  🔍 <b>Smarter Scanning</b>: Better detection of vulnerabilities<br>
  🔄 <b>Plan B Ready</b>: Added fallback options when tools fail<br>
  📡 <b>Better Network Handling</b>: Improved handling of connectivity issues<br>
  📊 <b>Versatile Results</b>: Support for different scan result formats
</p>

---

<h3 align="center">🔎 zotak-v3.py 🔎</h3>
<h4 align="center"><i>Expanded Capabilities</i></h4>

<div align="center">
  <table>
    <tr>
      <td align="center">
        <h5>🤖 New AI Option</h5>
        Added Google Gemini support alongside OpenRouter
      </td>
      <td align="center">
        <h5>📂 Better Directory Scanning</h5>
        Multiple tools working together seamlessly
      </td>
    </tr>
    <tr>
      <td align="center">
        <h5>🔆 Highlighted Results</h5>
        Improved visibility of important findings
      </td>
      <td align="center">
        <h5>🎯 Specialized Scans</h5>
        Added tools for specific vulnerability types
      </td>
    </tr>
    <tr>
      <td align="center" colspan="2">
        <h5>⏱️ Smoother Operation</h5>
        Better handling of long-running commands
      </td>
    </tr>
  </table>
</div>

---

<h3 align="center">🛠️ zotak_v2.py 🛠️</h3>
<h4 align="center"><i>Building Features</i></h4>

<div align="center">
  <span style="display: inline-block; width: 200px; text-align: center; margin: 10px;">
    <b>🔭 Better Reconnaissance</b><br>
    Enhanced scanning capabilities
  </span>
  <span style="display: inline-block; width: 200px; text-align: center; margin: 10px;">
    <b>🧐 Intelligent Analysis</b><br>
    Added scan result analysis
  </span>
  <span style="display: inline-block; width: 200px; text-align: center; margin: 10px;">
    <b>🎨 Style Options</b><br>
    Multiple prompt styles
  </span>
  <span style="display: inline-block; width: 200px; text-align: center; margin: 10px;">
    <b>⏱️ Timeout Handling</b><br>
    Better control of commands
  </span>
  <span style="display: inline-block; width: 200px; text-align: center; margin: 10px;">
    <b>💾 Result Storage</b><br>
    Organized results system
  </span>
</div>

---

<h3 align="center">🌱 zotak.py 🌱</h3>
<h4 align="center"><i>The Beginning</i></h4>

<p align="center">
  <b>📝 Basic Features</b>
</p>
<p align="center">
  Initial AI integration • Simple reconnaissance • Basic command execution • Terminal interface
</p>

---

## Collaboration

<div align="center">
  <h3>💻 Developed With Love 💻</h3>
  
  <p><b>Primary Developer:</b><br>
  ✨ <i>unknone hart</i> ✨</p>
  
  <p><b>In Collaboration With:</b></p>
  
  <table align="center">
    <tr>
      <td align="center">🔐 <b>deffhacker</b> 🔐</td>
      <td align="center">🛡️ <b>bitcops</b> 🛡️</td>
    </tr>
  </table>
  
  <p><i>Breaking systems through security, not devices</i></p>
</div>

## Upcoming Features

<div align="center">
  <h3>🔮 Coming Soon 🔮</h3>
  <p><i>Development actively in progress!</i></p>
  
  <table align="center" style="width: 80%">
    <tr>
      <td align="center">
        <h4>🌐 Web UI</h4>
        <p>Access Zotak's powerful capabilities through an intuitive browser interface</p>
      </td>
    </tr>
    <tr>
      <td align="center">
        <h4>🖥️ Graphical User Interface</h4>
        <p>Native GUI application with advanced visualization features</p>
      </td>
    </tr>
    <tr>
      <td align="center">
        <h4>🧠 Enhanced AI Models</h4>
        <p>Integration with more powerful AI models for improved accuracy and capabilities</p>
      </td>
    </tr>
  </table>
  
  <p><b>Stay tuned!</b> Follow the project for updates on these exciting new features.</p>
</div>

## Ethical Use

Zotak is designed for legitimate security testing with proper authorization. Unauthorized testing against systems you don't own or have explicit permission to test is illegal and unethical.

**IMPORTANT**: Only use this tool against systems you own or have explicit permission to test.

## License

This project is released under the MIT License.
