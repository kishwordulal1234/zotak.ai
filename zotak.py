#!/usr/bin/env python3

import os
import sys
import subprocess
import json
import time
import re
import signal
import requests
from datetime import datetime
import colorama
from colorama import Fore, Style
from openai import OpenAI
import shutil

# Import Google's Gemini API
try:
    import google.generativeai as genai
    GEMINI_AVAILABLE = True
except ImportError:
    GEMINI_AVAILABLE = False

# Initialize colorama for colored terminal output
colorama.init()

# Constants for saving results
RESULTS_DIR = os.path.expanduser("~/zotak_results")
os.makedirs(RESULTS_DIR, exist_ok=True)

# History log file for commands and responses
HISTORY_LOG = os.path.join(RESULTS_DIR, "command_history.log")

# API Keys and configuration
OPENROUTER_API_KEY = "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"
GEMINI_API_KEY = "AIzaSyBPu2W1OB8x1dDuOpO1X3V3Upf1YMKIihs"  # User's Gemini API key

# Default AI provider
DEFAULT_PROVIDER = "openrouter"  # Can be "openrouter" or "gemini"
DEFAULT_MODEL = "deepseek/deepseek-chat-v3-0324:free"  # OpenRouter model
GEMINI_MODEL = "gemini-2.0-flash"  # Google Gemini model

# Set up API clients
# OpenRouter API setup
openrouter_client = OpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=OPENROUTER_API_KEY,
    default_headers={
        "HTTP-Referer": "https://zotak-cli.com",
        "X-Title": "Zotak CLI"
    }
)

# Gemini API setup (will be initialized later if available)
gemini_client = None
if GEMINI_AVAILABLE:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
        gemini_client = genai.GenerativeModel(GEMINI_MODEL)
    except Exception as e:
        print(f"{Fore.RED}[-] Error setting up Gemini API: {str(e)}{Style.RESET_ALL}")

# Target info
target = None

# Running processes dictionary to keep track of active commands
active_processes = {}

# Last scan results
last_scan_output = None
last_scan_command = None

# ASCII Art Logo
ASCII_LOGO = """
███████╗ ██████╗ ████████╗ █████╗ ██╗  ██╗
╚══███╔╝██╔═══██╗╚══██╔══╝██╔══██╗██║ ██╔╝
  ███╔╝ ██║   ██║   ██║   ███████║█████╔╝ 
 ███╔╝  ██║   ██║   ██║   ██╔══██║██╔═██╗ 
███████╗╚██████╔╝   ██║   ██║  ██║██║  ██╗
╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝
        AI-Powered Pentesting CLI
"""

# Custom prompt styles
PROMPT_STYLES = [
    f"{Fore.BLUE}[H4X0R] > {Style.RESET_ALL}",
    f"{Fore.RED}[ZOTAK] ╞═► {Style.RESET_ALL}",
    f"{Fore.GREEN}What's your next move? 😈💀 {Style.RESET_ALL}",
    f"{Fore.MAGENTA}Ready to hack? 🔓 {Style.RESET_ALL}",
    f"{Fore.CYAN}[Z] Command: {Style.RESET_ALL}"
]
current_prompt_style = 0  # Index of the current prompt style

# Log command history
def log_command(command, response=None):
    """Log command history to file"""
    with open(HISTORY_LOG, "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"[{timestamp}] COMMAND: {command}\n")
        if response:
            log_file.write(f"[{timestamp}] RESPONSE: {response}\n")
        log_file.write("-" * 80 + "\n")

# Function to process AI requests with the selected provider
def query_ai(prompt, user_message, temperature=0.7):
    """Query the selected AI provider and return the response"""
    
    # Log API request
    print(f"{Fore.CYAN}[*] Processing...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[INFO] Querying {DEFAULT_PROVIDER.capitalize()} API" +
          (f" ({DEFAULT_MODEL})" if DEFAULT_PROVIDER == "openrouter" else f" ({GEMINI_MODEL})"))
    
    try:
        if DEFAULT_PROVIDER == "openrouter":
            # Use OpenRouter API
            completion = openrouter_client.chat.completions.create(
                model=DEFAULT_MODEL,
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": user_message}
                ],
                temperature=temperature
            )
            return completion.choices[0].message.content
        
        elif DEFAULT_PROVIDER == "gemini" and gemini_client:
            # Use Gemini API
            response = gemini_client.generate_content(
                [prompt, user_message]
            )
            return response.text
        else:
            raise Exception("Invalid AI provider or Gemini not available")
    
    except Exception as e:
        print(f"{Fore.RED}[-] Error querying AI: {str(e)}{Style.RESET_ALL}")
        return None

# Enhanced results display
def display_scan_results(title, results, highlight_keywords=None):
    """Display scan results with highlighting for important findings"""
    if not highlight_keywords:
        highlight_keywords = [
            "VULNERABLE", "CRITICAL", "HIGH", "CVE-", "EXPLOIT", 
            "DETECTED", "FOUND", "POSSIBLE", "SUCCESS", "INJECTION"
        ]
    
    print(f"\n{Fore.MAGENTA}╔══════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}║ {title.center(40)} ║{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}╚══════════════════════════════════════════╝{Style.RESET_ALL}")
    
    # Split results into lines and highlight important information
    lines = results.split('\n')
    for line in lines:
        highlighted = line
        for keyword in highlight_keywords:
            if keyword.lower() in line.lower():
                # Highlight the line with important findings
                highlighted = f"{Fore.RED}{line}{Style.RESET_ALL}"
                break
        print(highlighted)
    
    print(f"{Fore.MAGENTA}╔══════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}║ {' End of Results '.center(40)} ║{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}╚══════════════════════════════════════════╝{Style.RESET_ALL}")

# Run shell commands with enhanced output
def run_command(cmd, silent=False, show_progress=False, save_output=False):
    global last_scan_output, last_scan_command
    
    try:
        if not silent:
            print(f"{Fore.YELLOW}[*] Running: {cmd}{Style.RESET_ALL}")
        
        # Log command to history
        log_command(cmd)
        
        if show_progress:
            print(f"{Fore.CYAN}[*] Processing ", end="")
            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Store the process with a unique ID
            process_id = str(hash(cmd + str(time.time())))
            active_processes[process_id] = process
            
            # Show a simple progress indicator
            while process.poll() is None:
                print(".", end="", flush=True)
                time.sleep(0.5)
            
            # Remove process from active processes
            if process_id in active_processes:
                del active_processes[process_id]
            
            print(f"{Style.RESET_ALL}")
            stdout, stderr = process.communicate()
            result = process.returncode
        else:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if (result.returncode == 0 if not show_progress else result == 0):
            output = stdout if show_progress else result.stdout
            
            # Skip saving for viewing commands (cat, less, more, head, tail, etc.)
            viewing_commands = ["cat ", "less ", "more ", "head ", "tail ", "grep ", "view "]
            is_viewing_command = any(cmd.strip().startswith(view_cmd) for view_cmd in viewing_commands)
            
            # Save output if requested or if command contains common scan tools and is not a viewing command
            if (save_output or any(tool in cmd.lower() for tool in ["nmap", "gobuster", "dirb", "sqlmap", "nikto"])) and not is_viewing_command:
                # Save scan output to file
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                scan_type = "scan"
                
                # Try to determine scan type from command
                if "nmap" in cmd.lower():
                    scan_type = "nmap"
                elif "sqlmap" in cmd.lower():
                    scan_type = "sqlmap"
                elif "gobuster" in cmd.lower() or "dirb" in cmd.lower():
                    scan_type = "directory"
                elif "nikto" in cmd.lower():
                    scan_type = "nikto"
                elif "masscan" in cmd.lower():
                    scan_type = "masscan"
                elif "wpscan" in cmd.lower():
                    scan_type = "wpscan"
                elif "whatweb" in cmd.lower():
                    scan_type = "whatweb"
                
                # Create a descriptive filename
                target_str = target.replace(".", "_").replace("/", "").replace(":", "_") if target else "unknown"
                filename = f"{scan_type}_{target_str}_{timestamp}.txt"
                filepath = os.path.join(RESULTS_DIR, filename)
                
                # Save the output
                with open(filepath, 'w') as f:
                    f.write(f"Command: {cmd}\n")
                    f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Target: {target}\n")
                    f.write("-" * 80 + "\n\n")
                    f.write(output)
                
                print(f"{Fore.GREEN}[+] Scan results saved to: {filepath}{Style.RESET_ALL}")
                
                # Update last scan info
                last_scan_output = output
                last_scan_command = cmd
                
                # Create a symlink to the latest scan result of this type
                latest_link = os.path.join(RESULTS_DIR, f"latest_{scan_type}.txt")
                try:
                    if os.path.exists(latest_link):
                        os.remove(latest_link)
                    os.symlink(filepath, latest_link)
                except:
                    pass  # Ignore symlink errors on Windows
                
                # Analyze results for interesting findings if it's a scan
                if not is_viewing_command and scan_type in ["nmap", "sqlmap", "nikto"]:
                    analyze_scan_results(scan_type, output, cmd)
            
            if not silent:
                print(f"{Fore.GREEN}[+] Success{Style.RESET_ALL}")
                if len(output.strip()) > 0:
                    if len(output.strip()) < 500 or scan_type == "sqlmap":
                        # For shorter outputs or sqlmap, show everything
                        display_scan_results(f"{scan_type.upper()} RESULTS", output)
                    else:
                        # For longer outputs, show the first part
                        display_scan_results(f"{scan_type.upper()} RESULTS (TRUNCATED)", 
                                            "\n".join(output.strip().split('\n')[:20]) + 
                                            "\n... (See full results in saved file) ...")
            
            # Log response to history
            log_command(cmd, output[:500] + "..." if len(output) > 500 else output)
            
            return output
        else:
            err_output = stderr if show_progress else result.stderr
            # Check if error is due to missing tool
            if "command not found" in err_output or "not found" in err_output:
                # Extract the tool name
                tool_match = re.search(r"(\w+): [a-zA-Z ]*not found", err_output)
                if tool_match:
                    tool_name = tool_match.group(1)
                    print(f"{Fore.YELLOW}[!] Tool '{tool_name}' not found. Attempting to install...{Style.RESET_ALL}")
                    # Try to install the tool
                    if install_tool(tool_name):
                        # Retry the command
                        print(f"{Fore.GREEN}[+] Tool installed successfully. Retrying command...{Style.RESET_ALL}")
                        return run_command(cmd, silent, show_progress, save_output)
            
            # Handle common error cases
            if "Running Firefox as root" in err_output:
                print(f"{Fore.YELLOW}[!] Firefox cannot run as root. Using terminal-friendly alternative.{Style.RESET_ALL}")
                # Extract the report file
                report_match = re.search(r'-o\s+(\S+\.html)', cmd)
                if report_match:
                    html_file = report_match.group(1)
                    # Use w3m or lynx instead
                    if shutil.which("w3m"):
                        print(f"{Fore.GREEN}[+] Opening HTML report with w3m instead...{Style.RESET_ALL}")
                        return run_command(f"w3m {html_file}", silent, show_progress, False)
                    elif shutil.which("lynx"):
                        print(f"{Fore.GREEN}[+] Opening HTML report with lynx instead...{Style.RESET_ALL}")
                        return run_command(f"lynx {html_file}", silent, show_progress, False)
            
            print(f"{Fore.RED}[-] Error: {err_output.strip()}{Style.RESET_ALL}")
            return None
    except Exception as e:
        print(f"{Fore.RED}[-] Exception: {str(e)}{Style.RESET_ALL}")
        return None

# Analyze scan results for interesting findings
def analyze_scan_results(scan_type, output, cmd):
    """Analyze scan results and suggest possible exploits or next steps"""
    try:
        print(f"{Fore.YELLOW}[*] Analyzing {scan_type} results for interesting findings...{Style.RESET_ALL}")
        
        interesting_findings = []
        
        if scan_type == "nmap":
            # Look for open ports and services
            open_ports = re.findall(r'(\d+)/tcp\s+open\s+(\S+)', output)
            for port, service in open_ports:
                interesting_findings.append(f"Open port {port} running {service}")
            
            # Look for version info that might indicate vulnerable software
            version_info = re.findall(r'(\d+)/tcp\s+open\s+(\S+)\s+(.+)', output)
            for port, service, version in version_info:
                if any(v in version.lower() for v in ["apache", "nginx", "iis", "tomcat", "mysql", "ftp"]):
                    interesting_findings.append(f"Service {service} on port {port} running {version}")
        
        elif scan_type == "sqlmap":
            # Look for SQL injection findings
            if "GET parameter" in output and "is vulnerable" in output:
                vulnerable_params = re.findall(r'Parameter: ([^\s]+) \(([^\)]+)\)\s+Type: ([^\s]+)', output)
                for param, method, vuln_type in vulnerable_params:
                    interesting_findings.append(f"SQL Injection found: Parameter '{param}' is vulnerable to {vuln_type}")
            
            # Look for database details
            if "available databases" in output:
                dbs = re.findall(r'\[\*\] Available databases: \[([^\]]+)\]', output)
                if dbs:
                    interesting_findings.append(f"Databases found: {dbs[0]}")
            
            # Look for credentials or extracted data
            if "dumped to" in output:
                table_data = re.findall(r'Table ([^\s]+) dumped to', output)
                for table in table_data:
                    interesting_findings.append(f"Data extracted from table: {table}")
        
        # If we found interesting things, suggest next steps via AI
        if interesting_findings:
            findings_str = "\n".join(interesting_findings)
            print(f"{Fore.GREEN}[+] Interesting findings:{Style.RESET_ALL}")
            for finding in interesting_findings:
                print(f"{Fore.YELLOW}[!] {finding}{Style.RESET_ALL}")
            
            # Get AI suggestions for exploitation based on findings
            print(f"{Fore.CYAN}[*] Generating exploitation suggestions...{Style.RESET_ALL}")
            suggestion_prompt = f"""You are an expert penetration tester working with Kali Linux.
            
            Target: {target if target else "Unknown"}
            Scan type: {scan_type}
            Command used: {cmd}
            
            Interesting findings:
            {findings_str}
            
            Based on these findings, suggest 2-3 specific commands or techniques to exploit potential vulnerabilities.
            Keep your response short and focused on actionable commands. Format your response to be easy to read
            with bullet points if there are multiple suggestions.
            
            Return ONLY the suggestions without any introduction or explanation.
            """
            
            # Query AI for suggestions
            suggestions = query_ai(suggestion_prompt, f"Suggest exploits for {scan_type} findings", temperature=0.3)
            if suggestions:
                print(f"\n{Fore.GREEN}[+] Exploitation suggestions:{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{suggestions}{Style.RESET_ALL}")
    
    except Exception as e:
        print(f"{Fore.RED}[-] Error analyzing results: {str(e)}{Style.RESET_ALL}")

# Install missing tool
def install_tool(tool_name):
    print(f"{Fore.YELLOW}[!] Tool '{tool_name}' not found. Getting AI to generate installation command...{Style.RESET_ALL}")
    
    # Ask AI to generate installation command for the tool
    prompt = f"""You are a Kali Linux expert. Generate the command to install the tool '{tool_name}' on Kali Linux.
    Your response should be ONLY the exact command to run, without any explanation or formatting.
    Use apt-get or the most appropriate method for Kali Linux.
    If multiple methods exist, choose the most reliable/official one for Kali Linux.
    """
    
    try:
        response_text = query_ai(prompt, f"How do I install {tool_name} on Kali Linux?", temperature=0.3)
        
        if not response_text:
            print(f"{Fore.RED}[-] Failed to get installation command from AI{Style.RESET_ALL}")
            # Fallback to apt-get as a last resort
            print(f"{Fore.YELLOW}[*] Trying fallback installation with apt-get...{Style.RESET_ALL}")
            result = subprocess.run(f"apt-get update && apt-get install -y {tool_name}", shell=True, capture_output=True, text=True)
            return result.returncode == 0
            
        # Clean up command if it was returned with markdown
        install_cmd = re.sub(r'^```(?:bash|shell)?\s*', '', response_text)
        install_cmd = re.sub(r'\s*```$', '', install_cmd)
        
        # Ensure it's a simple command
        install_cmd = install_cmd.split('\n')[0]
        
        print(f"{Fore.YELLOW}[*] Running installation command: {install_cmd}{Style.RESET_ALL}")
        result = subprocess.run(install_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"{Fore.GREEN}[+] Successfully installed {tool_name}{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[-] Installation failed: {result.stderr}{Style.RESET_ALL}")
            # Fallback to apt-get as a last resort
            print(f"{Fore.YELLOW}[*] Trying fallback installation with apt-get...{Style.RESET_ALL}")
            result = subprocess.run(f"apt-get update && apt-get install -y {tool_name}", shell=True, capture_output=True, text=True)
            return result.returncode == 0
    
    except Exception as e:
        print(f"{Fore.RED}[-] Error generating installation command: {str(e)}{Style.RESET_ALL}")
        # Fallback to apt-get as a last resort
        print(f"{Fore.YELLOW}[*] Trying fallback installation with apt-get...{Style.RESET_ALL}")
        result = subprocess.run(f"apt-get update && apt-get install -y {tool_name}", shell=True, capture_output=True, text=True)
        return result.returncode == 0

# Kill all running processes
def kill_all_processes():
    if not active_processes:
        print(f"{Fore.YELLOW}[*] No active processes to kill{Style.RESET_ALL}")
        return
    
    count = 0
    for pid, process in list(active_processes.items()):
        try:
            if process.poll() is None:  # Process is still running
                process.terminate()
                count += 1
                # Remove from active processes
                del active_processes[pid]
        except:
            pass
    
    print(f"{Fore.GREEN}[+] Terminated {count} active processes{Style.RESET_ALL}")

# Show saved scan results
def show_scan_results(command=None):
    # If a specific scan is requested, show it
    if command:
        scan_type = None
        if "nmap" in command.lower():
            scan_type = "nmap"
        elif "sqlmap" in command.lower():
            scan_type = "sqlmap"
        elif "directory" in command.lower():
            scan_type = "directory"
        elif "nikto" in command.lower():
            scan_type = "nikto"
        
        if scan_type:
            latest_link = os.path.join(RESULTS_DIR, f"latest_{scan_type}.txt")
            if os.path.exists(latest_link):
                with open(latest_link, 'r') as f:
                    content = f.read()
                print(f"{Fore.GREEN}[+] Showing latest {scan_type} scan result:{Style.RESET_ALL}")
                display_scan_results(f"LATEST {scan_type.upper()} RESULTS", content)
                return
        
        # If we didn't find a specific scan type or it didn't exist
        print(f"{Fore.YELLOW}[*] Showing all recent scan results:{Style.RESET_ALL}")
    
    # List recent scan results
    scan_files = [f for f in os.listdir(RESULTS_DIR) if f.endswith('.txt') and not f.startswith('latest_')]
    scan_files.sort(key=lambda x: os.path.getmtime(os.path.join(RESULTS_DIR, x)), reverse=True)
    
    if scan_files:
        print(f"{Fore.GREEN}[+] Recent scan results:{Style.RESET_ALL}")
        for i, file in enumerate(scan_files[:10]):  # Show only the 10 most recent
            file_path = os.path.join(RESULTS_DIR, file)
            file_time = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
            print(f"{Fore.CYAN}[{i+1}] {file} - {file_time}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}[*] To view a scan, use: 'show scan [number]' or 'show scan [filename]'{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[*] No saved scan results found.{Style.RESET_ALL}")

# Enhanced recon function
def perform_enhanced_recon(target, fast=False):
    """Perform enhanced recon on a target with multiple tools"""
    if not target:
        print(f"{Fore.RED}[-] No target set. Use 'set target [hostname/IP]' first.{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}[+] Starting enhanced reconnaissance on {target}{Style.RESET_ALL}")
    
    if fast:
        print(f"{Fore.YELLOW}[*] Running fast recon mode{Style.RESET_ALL}")
        # Quick port scan
        run_command(f"nmap -T4 -F {target}", show_progress=True, save_output=True)
    else:
        print(f"{Fore.YELLOW}[*] Running comprehensive recon mode{Style.RESET_ALL}")
        
        # Step 1: Full port scan with service detection
        print(f"{Fore.CYAN}[*] Phase 1: Port scanning with service detection{Style.RESET_ALL}")
        run_command(f"nmap -sV -sC -A -T4 -p- {target}", show_progress=True, save_output=True)
        
        # Step 2: Web server fingerprinting
        print(f"{Fore.CYAN}[*] Phase 2: Web server fingerprinting{Style.RESET_ALL}")
        run_command(f"whatweb {target}", show_progress=True, save_output=True)
        
        # Step 3: Directory enumeration if it's a web target
        if "http" in target or target.endswith(".com") or target.endswith(".org") or target.endswith(".net"):
            print(f"{Fore.CYAN}[*] Phase 3: Directory enumeration{Style.RESET_ALL}")
            perform_dir_bruteforce(target)
    
    print(f"{Fore.GREEN}[+] Reconnaissance completed. Use 'show scan' to view results.{Style.RESET_ALL}")

# Improved directory brute forcing with multiple tools and timeout handling
def perform_dir_bruteforce(target, tool="auto", wordlist=None, timeout=60):
    """Perform directory brute forcing with better error handling"""
    if not target:
        print(f"{Fore.RED}[-] No target set. Use 'set target [hostname/IP]' first.{Style.RESET_ALL}")
        return
    
    # Format target URL properly
    if not target.startswith(("http://", "https://")):
        url = f"http://{target}"
    else:
        url = target
    
    # Use default wordlist if not specified
    if not wordlist:
        wordlist = "/usr/share/wordlists/dirb/common.txt"
    
    # Determine which tool to use
    if tool == "auto":
        tools = ["gobuster", "dirb", "dirsearch", "ffuf"]
        for t in tools:
            result = subprocess.run(f"which {t}", shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                tool = t
                break
    
    print(f"{Fore.CYAN}[*] Starting directory brute forcing with {tool}{Style.RESET_ALL}")
    
    # Command based on selected tool
    if tool == "gobuster":
        cmd = (f"gobuster dir -u {url} -w {wordlist} -t 10 "
               f"--timeout {timeout}s "
               f"--delay 500ms "
               f"-a 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36'")
    elif tool == "dirb":
        cmd = f"dirb {url} {wordlist} -a 'Mozilla/5.0' -z 500"
    elif tool == "dirsearch":
        cmd = f"dirsearch -u {url} -w {wordlist} -t 10 -e php,html,js -b"
    elif tool == "ffuf":
        cmd = f"ffuf -u {url}/FUZZ -w {wordlist} -t 10 -mc all -p 0.5"
    else:
        print(f"{Fore.RED}[-] No suitable directory brute forcing tool found.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Please install one of: gobuster, dirb, dirsearch, or ffuf{Style.RESET_ALL}")
        return
    
    # Run the command with timeout and retry logic
    try:
        output = run_command(cmd, show_progress=True, save_output=True)
        
        # If command failed, try an alternative tool
        if not output and tool == "gobuster":
            print(f"{Fore.YELLOW}[*] Gobuster failed. Trying dirb instead...{Style.RESET_ALL}")
            perform_dir_bruteforce(target, "dirb", wordlist, timeout)
    except Exception as e:
        print(f"{Fore.RED}[-] Error during directory brute forcing: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Trying alternative method...{Style.RESET_ALL}")
        if tool != "dirb":
            perform_dir_bruteforce(target, "dirb", wordlist, timeout)

# Signal handler for graceful exit
def signal_handler(sig, frame):
    # Kill all running processes before exiting
    kill_all_processes()
    
    print(f"\n{Fore.YELLOW}[*] Exiting...{Style.RESET_ALL}")
    sys.exit(0)

# Set up signal handlers
signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C

# AI-driven command generation and execution
def ai_process_command(command):
    global target, last_scan_output, DEFAULT_PROVIDER
    
    try:
        # Check for provider switching
        if command.lower() == "use openrouter":
            DEFAULT_PROVIDER = "openrouter"
            print(f"{Fore.GREEN}[+] Switched to OpenRouter API with model: {DEFAULT_MODEL}{Style.RESET_ALL}")
            return
        elif command.lower() == "use gemini" and gemini_client:
            DEFAULT_PROVIDER = "gemini"
            print(f"{Fore.GREEN}[+] Switched to Google Gemini API with model: {GEMINI_MODEL}{Style.RESET_ALL}")
            return
        elif command.lower() == "show provider":
            print(f"{Fore.GREEN}[+] Current AI provider: {DEFAULT_PROVIDER}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] OpenRouter model: {DEFAULT_MODEL}{Style.RESET_ALL}")
            if gemini_client:
                print(f"{Fore.GREEN}[+] Gemini model: {GEMINI_MODEL}{Style.RESET_ALL}")
            return
        
        # Check for "change prompt" command
        if command.lower() == "change prompt":
            global current_prompt_style
            current_prompt_style = (current_prompt_style + 1) % len(PROMPT_STYLES)
            print(f"{Fore.GREEN}[+] Prompt style changed{Style.RESET_ALL}")
            return
            
        # Check for "set target" command - handle typos like "set taarget"
        if re.search(r'set\s+t[a]*rget\s+', command.lower()):
            try:
                # Extract target from command
                match = re.search(r'set\s+t[a]*rget\s+(.*)', command)
                if match:
                    new_target = match.group(1).strip()
                    # Strip http:// and https:// from the URL if present
                    if new_target.lower().startswith("http://"):
                        new_target = new_target[7:]
                    elif new_target.lower().startswith("https://"):
                        new_target = new_target[8:]
                    target = new_target
                    print(f"{Fore.GREEN}[+] Target set to: {target}{Style.RESET_ALL}")
                    
                    # Also set environment variable for broader compatibility
                    os.environ["TARGET"] = target
                    
                    # Get AI to analyze the target if it's a domain
                    if '.' in target and not target.replace('.', '').isdigit():
                        print(f"{Fore.CYAN}[*] Getting target information...{Style.RESET_ALL}")
                        target_prompt = f"""You are a penetration testing expert. Analyze this target domain/URL and provide a brief summary.
                        
                        Target: {target}
                        
                        Include:
                        1. What type of target is this (e.g., known vulnerable test site, CMS, web app)?
                        2. What are typical vulnerabilities found in similar targets?
                        3. What should be the first few recon steps?
                        
                        Keep your response concise and actionable.
                        """
                        target_info = query_ai(target_prompt, f"Analyze target: {target}", temperature=0.5)
                        if target_info:
                            print(f"\n{Fore.CYAN}TARGET ANALYSIS:{Style.RESET_ALL}")
                            print(f"{Fore.WHITE}{target_info}{Style.RESET_ALL}\n")
                    
                    return
            except Exception as e:
                print(f"{Fore.RED}[-] Error setting target: {str(e)}{Style.RESET_ALL}")
                return
        
        # Check for enhanced recon command
        if command.lower() == "recon" or command.lower() == "full recon":
            perform_enhanced_recon(target, fast=False)
            return
        
        # Check for fast recon command
        if command.lower() == "fast recon" or command.lower() == "quick recon":
            perform_enhanced_recon(target, fast=True)
            return
        
        # Check for show scan results command
        if command.lower().startswith("show scan") or command.lower().startswith("show results"):
            parts = command.lower().split()
            if len(parts) > 2:
                # Check if the user specified a number or filename
                specifier = " ".join(parts[2:])
                if specifier.isdigit():
                    # Show scan by index
                    scan_files = [f for f in os.listdir(RESULTS_DIR) if f.endswith('.txt') and not f.startswith('latest_')]
                    scan_files.sort(key=lambda x: os.path.getmtime(os.path.join(RESULTS_DIR, x)), reverse=True)
                    idx = int(specifier) - 1
                    if 0 <= idx < len(scan_files):
                        with open(os.path.join(RESULTS_DIR, scan_files[idx]), 'r') as f:
                            content = f.read()
                        print(f"{Fore.GREEN}[+] Showing scan result: {scan_files[idx]}{Style.RESET_ALL}")
                        display_scan_results(f"SCAN RESULTS: {scan_files[idx]}", content)
                    else:
                        print(f"{Fore.RED}[-] Invalid scan number. Use 'show scan' to see available scans.{Style.RESET_ALL}")
                else:
                    # Check if it's a direct file path
                    if os.path.exists(specifier):
                        with open(specifier, 'r') as f:
                            content = f.read()
                        print(f"{Fore.GREEN}[+] Showing file: {specifier}{Style.RESET_ALL}")
                        display_scan_results(f"FILE: {os.path.basename(specifier)}", content)
                        return
                    
                    # Try to find by filename
                    for file in os.listdir(RESULTS_DIR):
                        if specifier in file.lower() and file.endswith('.txt'):
                            with open(os.path.join(RESULTS_DIR, file), 'r') as f:
                                content = f.read()
                            print(f"{Fore.GREEN}[+] Showing scan result: {file}{Style.RESET_ALL}")
                            display_scan_results(f"SCAN RESULTS: {file}", content)
                            return
                    print(f"{Fore.RED}[-] No scan results matching '{specifier}' found.{Style.RESET_ALL}")
            else:
                # Show list of available scans
                show_scan_results()
            return
        
        # Check for "improve it" command
        if command.lower() == "improve it" and last_scan_command:
            print(f"{Fore.YELLOW}[*] Generating improved version of last command...{Style.RESET_ALL}")
            # Build a prompt to improve the last command
            improvement_prompt = f"""You are an expert in Kali Linux penetration testing.
            
            The user previously ran this command: {last_scan_command}
            
            Generate an improved, more thorough version of this command that:
            1. Provides more detailed information
            2. Uses better flags/options
            3. Is more comprehensive in its analysis
            
            Target: {target if target else "Unknown"}
            
            Return ONLY a JSON with the improved command and explanation.
            """
            
            # Query AI for improved command
            response_text = query_ai(improvement_prompt, "Improve the previous scan command", temperature=0.7)
            
            try:
                # Try to parse the response as JSON
                response = None
                try:
                    # Try parsing directly
                    response = json.loads(response_text)
                except json.JSONDecodeError:
                    # If that fails, try to extract JSON from markdown code blocks
                    json_match = re.search(r'```(?:json)?\s*(.*?)\s*```', response_text, re.DOTALL)
                    if json_match:
                        try:
                            json_str = json_match.group(1).strip()
                            response = json.loads(json_str)
                        except:
                            pass
                
                if response and response.get("command"):
                    print(f"{Fore.BLUE}[*] {response.get('explanation', 'Improved scan command:')}{Style.RESET_ALL}")
                    cmd = response["command"]
                    print(f"{Fore.GREEN}[+] Executing improved command: {cmd}{Style.RESET_ALL}")
                    run_command(cmd, show_progress=True, save_output=True)
                    return
                else:
                    print(f"{Fore.YELLOW}[*] Failed to parse AI response. Continuing with normal command processing...{Style.RESET_ALL}")
            except:
                print(f"{Fore.YELLOW}[*] Failed to process improved command. Continuing with normal command processing...{Style.RESET_ALL}")
        
        # Add progress indicator for AI processing
        print(f"{Fore.CYAN}[*] Processing...{Style.RESET_ALL}")
        
        # Build the prompt for the AI
        prompt = f"""You are a pentesting AI assistant in a Kali Linux terminal.
        Generate a Kali Linux command to: {command}
        
        Assume all necessary tools are already installed. I'm using Kali Linux.
        
        Your task is to:
        1. Interpret the user's natural language command: "{command}"
        2. Generate appropriate Kali Linux commands.
        3. Return a JSON response with:
           - "command": The exact shell command to execute.
           - "explanation": Brief explanation of what the command does.

        Current target: {target if target else "Not set"}

        Return ONLY a valid JSON object.
        """
        
        # Query AI
        response_text = query_ai(prompt, command)
        if not response_text:
            print(f"{Fore.RED}[-] Failed to get AI response{Style.RESET_ALL}")
            return
        
        try:
            # Try to parse the response as JSON
            response = None
            try:
                # Try parsing directly
                response = json.loads(response_text)
            except json.JSONDecodeError:
                # If that fails, try to extract JSON from markdown code blocks
                json_match = re.search(r'```(?:json)?\s*(.*?)\s*```', response_text, re.DOTALL)
                if json_match:
                    try:
                        json_str = json_match.group(1).strip()
                        response = json.loads(json_str)
                    except:
                        pass
                        
                # If still no valid JSON, try to extract a command
                if not response:
                    print(f"{Fore.YELLOW}[*] AI returned non-JSON response, attempting to extract command...{Style.RESET_ALL}")
                    
                    # Simple extraction of a command if it exists in the text response
                    command_match = re.search(r'```(?:bash|shell)?\s*(.*?)\s*```', response_text, re.DOTALL)
                    if command_match:
                        extracted_command = command_match.group(1).strip()
                        response = {
                            "command": extracted_command,
                            "explanation": "Extracted command from AI response."
                        }
                    else:
                        # Try to find any command-like string in the response
                        lines = response_text.split('\n')
                        for line in lines:
                            if any(tool in line.lower() for tool in ["nmap", "gobuster", "sqlmap", "hydra", "msfconsole"]):
                                response = {
                                    "command": line.strip(),
                                    "explanation": "Extracted command from AI response."
                                }
                                break
                        else:
                            print(f"{Fore.RED}[-] Could not extract a usable command from AI response{Style.RESET_ALL}")
                            print(f"{Fore.CYAN}{response_text}{Style.RESET_ALL}")
                            return
            
            # Display explanation if available
            if response and response.get("explanation"):
                print(f"{Fore.BLUE}[*] {response['explanation']}{Style.RESET_ALL}")
            
            # Execute command if provided
            if response and response.get("command"):
                # Extract the actual command to run
                cmd = response["command"]
                
                # Replace target placeholder if a target is set
                if target:
                    placeholder_patterns = [
                        "<target>", "<target_ip>", "<target_IP>", "<TARGET>", 
                        "target_ip", "target_IP", "TARGET", "<host>", "<HOST>",
                        "\\$TARGET", "$TARGET", "\\${TARGET}"  # Environment variable formats
                    ]
                    
                    for pattern in placeholder_patterns:
                        cmd = cmd.replace(pattern, target)
                
                # Ask user confirmation for potentially dangerous commands
                dangerous_keywords = ["rm -rf", "dd if", "mkfs", "> /dev/sd"]
                if any(keyword in cmd for keyword in dangerous_keywords):
                    print(f"{Fore.RED}[!] Warning: This command may be destructive: {cmd}{Style.RESET_ALL}")
                    confirm = input(f"{Fore.YELLOW}[?] Are you sure you want to execute this command? (y/n): {Style.RESET_ALL}")
                    if confirm.lower() != 'y':
                        print(f"{Fore.RED}[*] Command execution aborted by user{Style.RESET_ALL}")
                        return
                
                # Execute the command
                print(f"{Fore.GREEN}[+] Executing in your Kali terminal: {cmd}{Style.RESET_ALL}")
                run_command(cmd, show_progress=True, save_output=True)
            else:
                print(f"{Fore.YELLOW}[*] No command to execute{Style.RESET_ALL}")
        
        except Exception as e:
            print(f"{Fore.RED}[-] Error parsing AI response: {str(e)}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{response_text}{Style.RESET_ALL}")
            return
            
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
        traceback = sys.exc_info()[2]
        print(f"{Fore.RED}[-] Traceback: {traceback.tb_frame.f_code.co_filename}:{traceback.tb_lineno}{Style.RESET_ALL}")

# Main CLI loop
def main():
    print(f"{Fore.MAGENTA}{ASCII_LOGO}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}Version 1.0 - Use this tool responsibly and legally{Style.RESET_ALL}")
    
    # Check if Gemini API is available
    if gemini_client:
        print(f"{Fore.GREEN}[+] Google Gemini API is available (use 'use gemini' to switch){Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] Google Gemini API not available. Using OpenRouter API only.{Style.RESET_ALL}")
        if not GEMINI_AVAILABLE:
            print(f"{Fore.YELLOW}[!] To use Gemini API, install the package: pip install google-generativeai{Style.RESET_ALL}")
    
    # Main loop
    print(f"{Fore.BLUE}Type 'exit' to quit, 'stop' to kill running scans, 'help' for assistance.{Style.RESET_ALL}")
    print(f"{Fore.BLUE}Type 'change prompt' to cycle through different prompt styles.{Style.RESET_ALL}")
    
    while True:
        try:
            user_input = input(PROMPT_STYLES[current_prompt_style]).strip()
            if user_input.lower() == "exit":
                kill_all_processes()  # Kill any running processes before exiting
                print(f"{Fore.YELLOW}[*] Exiting...{Style.RESET_ALL}")
                sys.exit(0)
            elif user_input.lower() == "stop" or user_input.lower() == "kill":
                kill_all_processes()
            elif user_input.lower() == "help":
                print(f"""
{Fore.MAGENTA}🔥 Zotak Help Menu 🔥{Style.RESET_ALL}

{Fore.CYAN}AI-Powered Commands:{Style.RESET_ALL}
  Just type what you want to do in natural language, the AI will handle it.
  No predefined commands or tool checking - AI will generate commands for you.

{Fore.CYAN}Example Natural Language Commands:{Style.RESET_ALL}
  "Scan testphp.vulnweb.com for SQL injection vulnerabilities"
  "Set up a man-in-the-middle attack on the network"
  "Generate a reverse shell payload for Windows 10 target at 192.168.1.5"
  "Crack the password for WPA handshake in capture.cap"
  "Find open ports on scanme.nmap.org and exploit any vulnerabilities"

{Fore.CYAN}Special Commands:{Style.RESET_ALL}
  set target [hostname/IP]  - Set the target for testing
  recon                     - Run comprehensive reconnaissance
  fast recon                - Run quick reconnaissance
  improve it                - Generate improved version of last command
  show scan                 - List recent scan results
  show scan [number/name]   - View specific scan result
  change prompt             - Change CLI prompt style
  use openrouter            - Switch to OpenRouter API
  use gemini                - Switch to Google Gemini API (if available)
  show provider             - Show current AI provider
  stop                      - Stop all running scans
  exit                      - Exit the application
                """)
            elif user_input.lower() == "":
                continue
            else:
                ai_process_command(user_input)
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[-] Interrupted. Type 'exit' to quit.")
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()