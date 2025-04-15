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
DEFAULT_PROVIDER = "openrouter"  # Can be "openrouter", "gemini", or "dual"
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

# Move the CommandContext class definition up before it's used
# Modify the CommandContext class to remove predefined commands
class CommandContext:
    def __init__(self):
        self.last_command = None
        self.last_command_type = None
        self.last_output = None
        self.target = None
        self.scan_history = []
        self.current_scan_type = None
    
    def update(self, command, command_type=None, output=None):
        self.last_command = command
        self.last_command_type = command_type
        self.current_scan_type = command_type
        if output:
            self.last_output = output
        if command_type:
            self.scan_history.append({
                'command': command,
                'type': command_type,
                'timestamp': datetime.now()
            })
    
    def get_context(self):
        return {
            'last_command': self.last_command,
            'last_command_type': self.last_command_type,
            'current_scan_type': self.current_scan_type,
            'target': self.target,
            'scan_history': self.scan_history[-5:] if self.scan_history else []
        }

# Custom prompt styles
PROMPT_STYLES = [
    f"{Fore.BLUE}[H4X0R] > {Style.RESET_ALL}",
    f"{Fore.RED}[ZOTAK] ╞═► {Style.RESET_ALL}",
    f"{Fore.GREEN}What's your next move? 😈💀 {Style.RESET_ALL}",
    f"{Fore.MAGENTA}Ready to hack? 🔓 {Style.RESET_ALL}",
    f"{Fore.CYAN}[Z] Command: {Style.RESET_ALL}"
]
current_prompt_style = 0  # Index of the current prompt style

# Initialize command context
command_context = CommandContext()

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
def query_ai(prompt, user_message, temperature=0.7, use_dual=False):
    """
    Query the selected AI provider and return the response
    If use_dual is True, it will query both providers and return the best response
    """
    
    # Log API request
    print(f"{Fore.CYAN}[*] Processing...{Style.RESET_ALL}")
    
    # Use dual mode if explicitly requested or if DEFAULT_PROVIDER is set to dual
    dual_mode = use_dual or DEFAULT_PROVIDER == "dual"
    
    if dual_mode and gemini_client:
        print(f"{Fore.YELLOW}[INFO] Querying both OpenRouter and Gemini APIs for enhanced results{Style.RESET_ALL}")
        
        # Query both providers in parallel
        openrouter_response = None
        gemini_response = None
        
        try:
            # Use OpenRouter API
            openrouter_response = openrouter_client.chat.completions.create(
                model=DEFAULT_MODEL,
                messages=[
                    {"role": "system", "content": prompt},
                    {"role": "user", "content": user_message}
                ],
                temperature=temperature
            ).choices[0].message.content
        except Exception as e:
            print(f"{Fore.RED}[-] OpenRouter API error: {str(e)}{Style.RESET_ALL}")
        
        try:
            # Use Gemini API
            gemini_response = gemini_client.generate_content(
                [prompt, user_message]
            ).text
        except Exception as e:
            print(f"{Fore.RED}[-] Gemini API error: {str(e)}{Style.RESET_ALL}")
        
        # Return the best response (prioritize the more detailed one)
        if openrouter_response and gemini_response:
            # Choose the longer, more detailed response
            if len(openrouter_response) > len(gemini_response) * 1.2:  # 20% longer threshold
                print(f"{Fore.GREEN}[+] Using OpenRouter response (more detailed){Style.RESET_ALL}")
                return openrouter_response
            elif len(gemini_response) > len(openrouter_response) * 1.2:
                print(f"{Fore.GREEN}[+] Using Gemini response (more detailed){Style.RESET_ALL}")
                return gemini_response
            else:
                # If similar length, choose OpenRouter (usually more suitable for security tasks)
                print(f"{Fore.GREEN}[+] Using OpenRouter response (similar detail levels){Style.RESET_ALL}")
                return openrouter_response
        elif openrouter_response:
            print(f"{Fore.GREEN}[+] Using OpenRouter response (Gemini failed){Style.RESET_ALL}")
            return openrouter_response
        elif gemini_response:
            print(f"{Fore.GREEN}[+] Using Gemini response (OpenRouter failed){Style.RESET_ALL}")
            return gemini_response
        else:
            raise Exception("Both AI providers failed to respond")
    
    # Single provider mode
    else:
        provider = DEFAULT_PROVIDER
        print(f"{Fore.YELLOW}[INFO] Querying {provider.capitalize()} API" +
              (f" ({DEFAULT_MODEL})" if provider == "openrouter" else f" ({GEMINI_MODEL})"))
        
        try:
            if provider == "openrouter":
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
            
            elif provider == "gemini" and gemini_client:
                # Use Gemini API
                response = gemini_client.generate_content(
                    [prompt, user_message]
                )
                return response.text
            else:
                raise Exception("Invalid AI provider or Gemini not available")
        
        except Exception as e:
            print(f"{Fore.RED}[-] Error querying {provider} API: {str(e)}{Style.RESET_ALL}")
            
            # Auto-fallback to the other provider if available
            if provider == "openrouter" and gemini_client:
                print(f"{Fore.YELLOW}[*] Falling back to Gemini API...{Style.RESET_ALL}")
                try:
                    response = gemini_client.generate_content(
                        [prompt, user_message]
                    )
                    return response.text
                except Exception as fallback_error:
                    print(f"{Fore.RED}[-] Fallback also failed: {str(fallback_error)}{Style.RESET_ALL}")
            
            elif provider == "gemini":
                print(f"{Fore.YELLOW}[*] Falling back to OpenRouter API...{Style.RESET_ALL}")
                try:
                    completion = openrouter_client.chat.completions.create(
                        model=DEFAULT_MODEL,
                        messages=[
                            {"role": "system", "content": prompt},
                            {"role": "user", "content": user_message}
                        ],
                        temperature=temperature
                    )
                    return completion.choices[0].message.content
                except Exception as fallback_error:
                    print(f"{Fore.RED}[-] Fallback also failed: {str(fallback_error)}{Style.RESET_ALL}")
            
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
        
        # Check if this is a file reading command
        is_file_read = any(cmd.strip().startswith(read_cmd) for read_cmd in ["cat ", "less ", "more ", "head ", "tail ", "grep "])
        
        # Check if this is a compound command with pipes or redirects
        is_compound_command = any(operator in cmd for operator in ["|", "&&", "||", ">", ">>"])
        
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
            
            # Handle file reading commands differently
            if is_file_read:
                if len(output.strip()) > 0:
                    display_scan_results("FILE CONTENTS", output)
                else:
                    print(f"{Fore.RED}[-] File not found or empty{Style.RESET_ALL}")
                return output
            
            # Skip saving for viewing commands
            viewing_commands = ["cat ", "less ", "more ", "head ", "tail ", "grep ", "view "]
            is_viewing_command = any(cmd.strip().startswith(view_cmd) for view_cmd in viewing_commands)
            
            # Save output if requested or if command contains common scan tools and is not a viewing command
            if (save_output or any(tool in cmd.lower() for tool in ["nmap", "gobuster", "dirb", "sqlmap", "nikto", "whois"])) and not is_viewing_command:
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
                elif "whois" in cmd.lower():
                    scan_type = "whois"
                
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
                if not is_viewing_command and scan_type in ["nmap", "sqlmap", "nikto", "whois"]:
                    analyze_scan_results(scan_type, output, cmd)
            
            if not silent and not is_file_read:  # Don't show success message for file reads
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
            
            # Enhanced error handling for compound commands
            if is_compound_command:
                # Check for common error patterns in compound commands
                if "grep: " in err_output and "No such file or directory" in err_output:
                    print(f"{Fore.RED}[-] Error: The 'grep' command failed because the input file was not found{Style.RESET_ALL}")
                elif "dig: couldn't get address for" in err_output and "not found" in err_output:
                    print(f"{Fore.RED}[-] Error: DNS resolution failed - no nameserver could be found in the previous command output{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Tip: Check that the domain exists and has valid nameserver records{Style.RESET_ALL}")
                elif "awk: " in err_output and "not found" in err_output:
                    print(f"{Fore.RED}[-] Error: The 'awk' command failed to find a matching pattern in the previous command output{Style.RESET_ALL}")
                elif "host: " in err_output and "not found" in err_output:
                    print(f"{Fore.RED}[-] Error: The 'host' command could not resolve the provided domain{Style.RESET_ALL}")
                else:
                    # Generic error for compound commands
                    print(f"{Fore.RED}[-] Error in compound command: {err_output.strip()}{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[*] Tip: In compound commands (using | or &&), each part depends on the previous part's success{Style.RESET_ALL}")
            else:
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
                else:
                    print(f"{Fore.RED}[-] Error: {err_output.strip()}{Style.RESET_ALL}")
            
            return None
    except Exception as e:
        print(f"{Fore.RED}[-] Exception: {str(e)}{Style.RESET_ALL}")
        return None

# Analyze scan results for interesting findings
def analyze_scan_results(scan_type, output, cmd):
    """Analyze scan results using AI and suggest possible exploits or next steps with severity ratings"""
    global DEFAULT_PROVIDER
    
    try:
        print(f"{Fore.YELLOW}[*] Analyzing {scan_type} results for interesting findings...{Style.RESET_ALL}")
        
        # Create a more structured prompt for AI analysis with emphasis on severity ratings
        analysis_prompt = f"""You are an expert penetration tester working with Kali Linux.
        
        Analyze the following scan results and identify interesting findings and potential vulnerabilities:
        
        Target: {target if target else "Unknown"}
        Scan type: {scan_type}
        Command used: {cmd}
        
        Scan output:
        {output[:3000]}  # Limit output length to avoid token limits
        
        Please identify:
        1. Security issues, vulnerabilities, or attack vectors
        2. Interesting configurations, services, or exposures
        3. Valuable information for further attacks
        4. Overall security posture insights
        
        IMPORTANT: Return a JSON with precisely this structure:
        {{
            "findings": [
                {{
                    "description": "Detailed description of finding",
                    "severity": "critical|high|medium|low|info"
                }},
                // Additional findings...
            ],
            "suggested_commands": [
                "Command 1 with full syntax ready to execute",
                "Command 2 with full syntax ready to execute",
                "Command 3 with full syntax ready to execute"
            ],
            "explanation": "Brief analysis explaining the significance of these findings and why the suggested commands are appropriate next steps"
        }}
        
        For severity ratings:
        - "critical": Immediate compromise possible
        - "high": Direct security impact, exploit likely
        - "medium": Security weakness requiring attention
        - "low": Minor security concern
        - "info": Informational only
        
        Ensure commands are precise with exact syntax, ready to run, and targeted toward exploiting or investigating the findings further.
        """
        
        # Use the currently selected provider for analysis
        print(f"{Fore.CYAN}[*] Processing...{Style.RESET_ALL}")
        
        # Display which AI is being used for enhanced analysis
        if DEFAULT_PROVIDER == "dual" and gemini_client:
            print(f"{Fore.CYAN}[INFO] Querying both OpenRouter and Gemini APIs for enhanced results{Style.RESET_ALL}")
            use_dual = True
        elif DEFAULT_PROVIDER == "gemini" and gemini_client:
            print(f"{Fore.CYAN}[INFO] Querying Gemini API for enhanced results{Style.RESET_ALL}")
            use_dual = False
        else:
            print(f"{Fore.CYAN}[INFO] Querying OpenRouter API for enhanced results{Style.RESET_ALL}")
            use_dual = False
        
        # Query AI for analysis with the appropriate provider
        response_text = query_ai(analysis_prompt, f"Analyze {scan_type} scan results", temperature=0.5, use_dual=use_dual)
        
        try:
            # Parse the response
            response = None
            try:
                response = json.loads(response_text)
            except json.JSONDecodeError:
                # Try to extract JSON from markdown code blocks
                json_match = re.search(r'```(?:json)?\s*(.*?)\s*```', response_text, re.DOTALL)
                if json_match:
                    try:
                        json_str = json_match.group(1).strip()
                        response = json.loads(json_str)
                    except:
                        pass
            
            # Display findings and suggestions with enhanced formatting
            if response:
                # Display findings with severity coloring
                if response.get("findings"):
                    print(f"\n{Fore.GREEN}[+] Key findings:{Style.RESET_ALL}")
                    for finding in response["findings"]:
                        # Set color based on severity
                        severity = finding.get("severity", "info").lower()
                        if severity == "critical":
                            severity_color = Fore.RED + Style.BRIGHT
                        elif severity == "high":
                            severity_color = Fore.RED
                        elif severity == "medium":
                            severity_color = Fore.YELLOW
                        elif severity == "low":
                            severity_color = Fore.BLUE
                        else:  # info
                            severity_color = Fore.CYAN
                        
                        # Print with appropriate color
                        print(f"{Fore.YELLOW}[!] {severity_color}{finding}{Style.RESET_ALL}")
                
                # Display suggested commands with numbers
                if response.get("suggested_commands"):
                    print(f"\n{Fore.GREEN}[+] Suggested follow-up commands:{Style.RESET_ALL}")
                    for i, command in enumerate(response["suggested_commands"]):
                        print(f"{Fore.CYAN}[{i+1}] {command}{Style.RESET_ALL}")
                
                # Display explanation if available
                if response.get("explanation"):
                    print(f"\n{Fore.MAGENTA}[+] Analysis summary:{Style.RESET_ALL}")
                    print(f"{Fore.WHITE}{response['explanation']}{Style.RESET_ALL}")
                
                # Save the analysis to a file for reference
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                analysis_file = os.path.join(RESULTS_DIR, f"analysis_{target.replace('.', '_')}_{scan_type}_{timestamp}.json")
                with open(analysis_file, 'w') as f:
                    json.dump(response, f, indent=2)
                print(f"{Fore.GREEN}[+] Analysis saved to: {analysis_file}{Style.RESET_ALL}")
                
                return True
            
            # If response parsing failed, ask if user wants to see raw output
            else:
                print(f"{Fore.YELLOW}[*] AI response could not be parsed in the expected format.{Style.RESET_ALL}")
                user_choice = input(f"{Fore.YELLOW}[?] Show raw analysis output? (y/n): {Style.RESET_ALL}").strip().lower()
                
                if user_choice == 'y':
                    print(f"\n{Fore.GREEN}[+] Raw scan analysis:{Style.RESET_ALL}")
                    print(f"{Fore.CYAN}{response_text}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[*] Analysis display skipped.{Style.RESET_ALL}")
                
                return True
                
        except Exception as e:
            print(f"{Fore.RED}[-] Error processing analysis results: {str(e)}{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"{Fore.RED}[-] Error analyzing results: {str(e)}{Style.RESET_ALL}")
        return False

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

# Track scan history
def get_scan_history():
    """Get a list of all scan results, sorted by date"""
    scan_files = []
    try:
        for file in os.listdir(RESULTS_DIR):
            if file.endswith('.txt') and not file.startswith('latest_'):
                file_path = os.path.join(RESULTS_DIR, file)
                scan_files.append({
                    'filename': file,
                    'path': file_path,
                    'mtime': os.path.getmtime(file_path),
                    'type': file.split('_')[0] if '_' in file else 'unknown'
                })
        
        # Sort by modification time, newest first
        scan_files.sort(key=lambda x: x['mtime'], reverse=True)
        return scan_files
    except Exception as e:
        print(f"{Fore.RED}[-] Error reading scan history: {str(e)}{Style.RESET_ALL}")
        return []

# Show saved scan results
def show_scan_results(command=None):
    # Get all scan files
    scan_files = get_scan_history()
    
    # If a specific scan is requested
    if command:
        # First try to find by scan type
        scan_type = None
        if "nmap" in command.lower():
            scan_type = "nmap"
        elif "sqlmap" in command.lower():
            scan_type = "sqlmap"
        elif "directory" in command.lower():
            scan_type = "directory"
        elif "nikto" in command.lower():
            scan_type = "nikto"
        elif "whois" in command.lower():
            scan_type = "whois"
        
        # Try to find the latest scan of the requested type
        if scan_type:
            latest_file = None
            for scan in scan_files:
                if scan['type'] == scan_type:
                    latest_file = scan
                    break
            
            if latest_file:
                try:
                    with open(latest_file['path'], 'r') as f:
                        content = f.read()
                    print(f"{Fore.GREEN}[+] Showing latest {scan_type} scan result:{Style.RESET_ALL}")
                    display_scan_results(f"LATEST {scan_type.upper()} RESULTS", content)
                    return
                except Exception as e:
                    print(f"{Fore.RED}[-] Error reading scan file: {str(e)}{Style.RESET_ALL}")
        
        # If we get here, try to find the file by name or number
        try:
            if command.isdigit():
                # Show scan by index
                idx = int(command) - 1
                if 0 <= idx < len(scan_files):
                    with open(scan_files[idx]['path'], 'r') as f:
                        content = f.read()
                    print(f"{Fore.GREEN}[+] Showing scan result: {scan_files[idx]['filename']}{Style.RESET_ALL}")
                    display_scan_results(f"SCAN RESULTS: {scan_files[idx]['filename']}", content)
                    return
            else:
                # Try to find by filename
                for scan in scan_files:
                    if command.lower() in scan['filename'].lower():
                        with open(scan['path'], 'r') as f:
                            content = f.read()
                        print(f"{Fore.GREEN}[+] Showing scan result: {scan['filename']}{Style.RESET_ALL}")
                        display_scan_results(f"SCAN RESULTS: {scan['filename']}", content)
                        return
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[*] No matching scan results found. Showing all recent scans:{Style.RESET_ALL}")
    
    # List recent scan results
    if scan_files:
        print(f"{Fore.GREEN}[+] Recent scan results:{Style.RESET_ALL}")
        for i, scan in enumerate(scan_files[:10]):  # Show only the 10 most recent
            file_time = datetime.fromtimestamp(scan['mtime']).strftime('%Y-%m-%d %H:%M:%S')
            print(f"{Fore.CYAN}[{i+1}] {scan['filename']} - {file_time}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}[*] To view a scan, use: 'show scan [number]' or 'show scan [filename]'{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[*] No saved scan results found.{Style.RESET_ALL}")

# Enhanced recon function
def perform_enhanced_recon(target, fast=False):
    """Perform enhanced recon on a target with AI-generated commands"""
    global command_context, DEFAULT_PROVIDER
    
    if not target:
        print(f"{Fore.RED}[-] No target set. Use 'set target [hostname/IP]' first.{Style.RESET_ALL}")
        return
    
    print(f"{Fore.GREEN}[+] Starting enhanced reconnaissance on {target}{Style.RESET_ALL}")
    
    # Use AI to generate appropriate recon commands with structured output
    recon_prompt = f"""You are a penetration testing expert. Generate a comprehensive reconnaissance plan for the target.
    
    Target: {target}
    Recon mode: {"Fast (quick scan of common services)" if fast else "Comprehensive (thorough enumeration)"}
    
    Create a detailed, systematic reconnaissance plan with specific commands to execute.
    
    IMPORTANT: Return a JSON with the following structure:
    {{
        "plan_description": "Brief description of the overall reconnaissance strategy",
        "plan_phases": [
            {{
                "phase_name": "Initial Footprinting",
                "phase_goal": "Discover basic information about the target",
                "commands": [
                    {{
                        "command": "Exact command to run with all parameters",
                        "explanation": "What this command does and why it's important",
                        "type": "Command type (e.g., 'nmap', 'whois', etc.)",
                        "expected_findings": [
                            {{
                                "description": "What this command might discover",
                                "severity": "critical|high|medium|low|info"
                            }}
                            // 1-2 more expected findings
                        ]
                    }}
                    // More commands for this phase
                ]
            }}
            // More phases as appropriate
        ]
    }}
    
    For severity ratings:
    - "critical": Immediate compromise possible
    - "high": Direct security impact, exploit likely  
    - "medium": Security weakness requiring attention
    - "low": Minor security concern
    - "info": Informational only
    
    Plan phases should follow a logical progression from initial information gathering to more targeted scanning.
    If fast mode, limit to 2-3 phases with 1-2 commands each.
    If comprehensive mode, include 3-5 phases with 2-3 commands each.
    
    Ensure all commands have proper syntax and are ready to execute.
    """
    
    # Use the currently selected provider for generating the recon plan
    print(f"{Fore.CYAN}[*] Generating reconnaissance plan...{Style.RESET_ALL}")
    
    # Display which AI is being used
    use_dual = False
    if DEFAULT_PROVIDER == "dual" and gemini_client:
        print(f"{Fore.CYAN}[INFO] Querying both OpenRouter and Gemini APIs for enhanced results{Style.RESET_ALL}")
        use_dual = True
    elif DEFAULT_PROVIDER == "gemini" and gemini_client:
        print(f"{Fore.CYAN}[INFO] Querying Gemini API for enhanced results{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}[INFO] Querying OpenRouter API for enhanced results{Style.RESET_ALL}")
    
    response_text = query_ai(recon_prompt, f"Generate {'fast' if fast else 'comprehensive'} recon plan", temperature=0.5, use_dual=use_dual)
    
    try:
        # Parse the response as JSON
        recon_plan = None
        try:
            # Try parsing directly
            recon_plan = json.loads(response_text)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            json_match = re.search(r'```(?:json)?\s*(.*?)\s*```', response_text, re.DOTALL)
            if json_match:
                try:
                    json_str = json_match.group(1).strip()
                    recon_plan = json.loads(json_str)
                except:
                    pass
        
        # If we got a valid recon plan with the expected structure
        if recon_plan and recon_plan.get("plan_phases"):
            # Display the recon plan overview
            if recon_plan.get("plan_description"):
                print(f"\n{Fore.MAGENTA}[+] Recon Strategy: {recon_plan['plan_description']}{Style.RESET_ALL}")
            
            # Save the recon plan to a file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            plan_file = os.path.join(RESULTS_DIR, f"recon_plan_{target.replace('.', '_')}_{timestamp}.json")
            with open(plan_file, 'w') as f:
                json.dump(recon_plan, f, indent=2)
            print(f"{Fore.GREEN}[+] Reconnaissance plan saved to: {plan_file}{Style.RESET_ALL}")
            
            # Execute each phase of the plan
            for phase_idx, phase in enumerate(recon_plan["plan_phases"]):
                phase_name = phase.get("phase_name", f"Phase {phase_idx+1}")
                phase_goal = phase.get("phase_goal", "Execute reconnaissance commands")
                
                print(f"\n{Fore.BLUE}{'='*80}{Style.RESET_ALL}")
                print(f"{Fore.BLUE}[+] PHASE {phase_idx+1}: {phase_name}{Style.RESET_ALL}")
                print(f"{Fore.BLUE}[+] Goal: {phase_goal}{Style.RESET_ALL}")
                print(f"{Fore.BLUE}{'='*80}{Style.RESET_ALL}")
                
                # Execute each command in this phase
                commands = phase.get("commands", [])
                for cmd_idx, cmd_info in enumerate(commands):
                    if isinstance(cmd_info, dict) and cmd_info.get("command"):
                        print(f"\n{Fore.CYAN}[*] Step {phase_idx+1}.{cmd_idx+1}: {cmd_info.get('explanation', 'Running command...')}{Style.RESET_ALL}")
                        cmd = cmd_info["command"]
                        cmd_type = cmd_info.get("type", "recon")
                        
                        # Display expected findings
                        if cmd_info.get("expected_findings"):
                            print(f"\n{Fore.GREEN}[+] Expected findings:{Style.RESET_ALL}")
                            for finding in cmd_info["expected_findings"]:
                                # Set color based on severity
                                severity = finding.get("severity", "info").lower()
                                if severity == "critical":
                                    severity_color = Fore.RED + Style.BRIGHT
                                elif severity == "high":
                                    severity_color = Fore.RED
                                elif severity == "medium":
                                    severity_color = Fore.YELLOW
                                elif severity == "low":
                                    severity_color = Fore.BLUE
                                else:  # info
                                    severity_color = Fore.CYAN
                                
                                # Print with appropriate color
                                print(f"{Fore.YELLOW}  [!] {severity_color}{finding}{Style.RESET_ALL}")
                        
                        # Execute the command
                        print(f"\n{Fore.GREEN}[+] Executing: {cmd}{Style.RESET_ALL}")
                        output = run_command(cmd, show_progress=True, save_output=True)
                        
                        # Update context
                        if output:
                            command_context.update(cmd, cmd_type, output)
                        
                        # Check if user wants to continue or abort
                        if cmd_idx < len(commands) - 1 or phase_idx < len(recon_plan["plan_phases"]) - 1:
                            print(f"{Fore.YELLOW}[*] Press Enter to continue to next step or type 'abort' to stop: {Style.RESET_ALL}", end="")
                            user_input = input().strip().lower()
                            if user_input == "abort":
                                print(f"{Fore.RED}[*] Reconnaissance aborted by user{Style.RESET_ALL}")
                                return
            
            print(f"\n{Fore.GREEN}[+] Reconnaissance completed. Use 'show scan' to view results.{Style.RESET_ALL}")
            
        else:
            print(f"{Fore.RED}[-] Failed to generate a valid reconnaissance plan. Using fallback method.{Style.RESET_ALL}")
            fallback_recon(target, fast)
    
    except Exception as e:
        print(f"{Fore.RED}[-] Error during reconnaissance planning: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Using fallback reconnaissance method{Style.RESET_ALL}")
        fallback_recon(target, fast)

# Fallback recon function if AI fails
def fallback_recon(target, fast=False):
    """Fallback method for recon if AI generation fails"""
    print(f"{Fore.YELLOW}[*] AI failed to generate a reconnaissance plan.{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[*] Would you like to use predefined basic commands instead?{Style.RESET_ALL}")
    user_choice = input(f"{Fore.YELLOW}[?] Use predefined commands? (y/n): {Style.RESET_ALL}").strip().lower()
    
    if user_choice != 'y':
        print(f"{Fore.RED}[*] Reconnaissance aborted. No predefined commands will be run.{Style.RESET_ALL}")
        return
    
    if fast:
        print(f"{Fore.YELLOW}[*] Running basic port scan (fast mode){Style.RESET_ALL}")
        run_command(f"nmap -F -T4 {target}", show_progress=True, save_output=True)
    else:
        print(f"{Fore.YELLOW}[*] Running comprehensive port scan{Style.RESET_ALL}")
        run_command(f"nmap -sV -sC -p- -T4 {target}", show_progress=True, save_output=True)
        
        # Basic web check
        print(f"{Fore.YELLOW}[*] Checking for web services{Style.RESET_ALL}")
        run_command(f"whatweb {target}", show_progress=True, save_output=True)

# Signal handler for graceful exit
def signal_handler(sig, frame):
    # Kill all running processes before exiting
    kill_all_processes()
    
    print(f"\n{Fore.YELLOW}[*] Exiting...{Style.RESET_ALL}")
    sys.exit(0)

# Set up signal handlers
signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C

# Modify the ai_process_command function to be fully AI-driven
def ai_process_command(command):
    global target, last_scan_output, DEFAULT_PROVIDER, command_context, current_prompt_style
    
    try:
        # Handle provider switching and basic commands first
        if command.lower() == "use openrouter":
            DEFAULT_PROVIDER = "openrouter"
            print(f"{Fore.GREEN}[+] Switched to OpenRouter API with model: {DEFAULT_MODEL}{Style.RESET_ALL}")
            return
        elif command.lower() == "use gemini" and gemini_client:
            DEFAULT_PROVIDER = "gemini"
            print(f"{Fore.GREEN}[+] Switched to Google Gemini API with model: {GEMINI_MODEL}{Style.RESET_ALL}")
            return
        elif command.lower() == "use dual" and gemini_client:
            DEFAULT_PROVIDER = "dual"
            print(f"{Fore.GREEN}[+] Switched to dual AI mode - using both OpenRouter and Gemini APIs{Style.RESET_ALL}")
            return
        elif command.lower() == "show provider":
            print(f"{Fore.GREEN}[+] Current AI provider: {DEFAULT_PROVIDER}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[+] OpenRouter model: {DEFAULT_MODEL}{Style.RESET_ALL}")
            if gemini_client:
                print(f"{Fore.GREEN}[+] Gemini model: {GEMINI_MODEL}{Style.RESET_ALL}")
            return
        elif command.lower() == "change prompt":
            current_prompt_style = (current_prompt_style + 1) % len(PROMPT_STYLES)
            print(f"{Fore.GREEN}[+] Prompt style changed{Style.RESET_ALL}")
            return
        
        # Handle recon commands
        if command.lower() == "recon" or command.lower() == "full recon":
            perform_enhanced_recon(target, fast=False)
            return
        elif command.lower() == "fast recon" or command.lower() == "quick recon":
            perform_enhanced_recon(target, fast=True)
            return
        
        # Handle scan results viewing
        if command.lower().startswith("show scan") or command.lower().startswith("show results"):
            parts = command.lower().split()
            if len(parts) > 2:
                show_scan_results(" ".join(parts[2:]))
            else:
                show_scan_results()
            return

        # Handle advanced command requests - Fully AI-driven
        if any(cmd in command.lower() for cmd in ["more advance", "more advanced", "advance", "advanced"]):
            context = command_context.get_context()
            current_scan_type = context.get('current_scan_type')
            last_command = context.get('last_command')
            
            if not current_scan_type or not last_command:
                print(f"{Fore.YELLOW}[!] No previous command context found. Please run a scan first.{Style.RESET_ALL}")
                return False
                
            # Create a more structured prompt for advanced command generation
            advanced_prompt = f"""You are a penetration testing expert. Generate an advanced command sequence based on the user's previous action.

            Previous command: {last_command}
            Previous command type: {current_scan_type}
            Target: {target if target else "Unknown"}
            
            Create a more powerful, comprehensive command sequence that:
            1. Builds upon the previous {current_scan_type} command
            2. Adds more detailed scanning/enumeration options
            3. Reveals more information than the original command
            4. Uses appropriate offensive security tools available in Kali Linux
            
            IMPORTANT: Return a JSON with this precise structure:
            {{
                "command": "The exact command to run with full syntax",
                "explanation": "Thorough explanation of what the command does and how it's better than the previous command",
                "type": "Command type (e.g., 'nmap_advanced', 'whois_enhanced', etc.)",
                "improvements": [
                    "Specific improvement point 1 over the previous command",
                    "Specific improvement point 2 over the previous command",
                    "Specific improvement point 3 over the previous command"
                ],
                "expected_findings": [
                    {{
                        "description": "What this command might discover",
                        "severity": "critical|high|medium|low|info"
                    }}
                    // 2-3 more expected findings
                ]
            }}
            
            For severity ratings:
            - "critical": Immediate compromise possible
            - "high": Direct security impact, exploit likely
            - "medium": Security weakness requiring attention
            - "low": Minor security concern
            - "info": Informational only
            
            Ensure the command is precise with exact syntax, ready to run, and targeted to find high-value information. Prioritize thoroughness and accuracy over speed.
            """
            
            # Use the currently selected provider for generating advanced commands
            print(f"{Fore.CYAN}[*] Generating advanced command...{Style.RESET_ALL}")
            
            # Display which AI is being used for enhanced generation
            use_dual = False
            if DEFAULT_PROVIDER == "dual" and gemini_client:
                print(f"{Fore.CYAN}[INFO] Querying both OpenRouter and Gemini APIs for enhanced results{Style.RESET_ALL}")
                use_dual = True
            elif DEFAULT_PROVIDER == "gemini" and gemini_client:
                print(f"{Fore.CYAN}[INFO] Querying Gemini API for enhanced results{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}[INFO] Querying OpenRouter API for enhanced results{Style.RESET_ALL}")
            
            response_text = query_ai(advanced_prompt, f"Generate advanced version of {current_scan_type} command", temperature=0.5, use_dual=use_dual)
            
            try:
                # Parse the response as JSON
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
                
                # Process structured response
                if response and response.get("command"):
                    # Display command and explanation
                    print(f"{Fore.BLUE}[*] {response.get('explanation', 'Enhanced command:')}{Style.RESET_ALL}")
                    cmd = response["command"]
                    cmd_type = response.get("type", f"{current_scan_type}_advanced")
                    
                    # Display improvements as a list
                    if response.get("improvements"):
                        print(f"\n{Fore.GREEN}[+] Improvements over previous command:{Style.RESET_ALL}")
                        for i, improvement in enumerate(response["improvements"]):
                            print(f"{Fore.CYAN}  {i+1}. {improvement}{Style.RESET_ALL}")
                    
                    # Display expected findings with severity
                    if response.get("expected_findings"):
                        print(f"\n{Fore.GREEN}[+] Expected findings:{Style.RESET_ALL}")
                        for finding in response["expected_findings"]:
                            # Set color based on severity
                            severity = finding.get("severity", "info").lower()
                            if severity == "critical":
                                severity_color = Fore.RED + Style.BRIGHT
                            elif severity == "high":
                                severity_color = Fore.RED
                            elif severity == "medium":
                                severity_color = Fore.YELLOW
                            elif severity == "low":
                                severity_color = Fore.BLUE
                            else:  # info
                                severity_color = Fore.CYAN
                            
                            # Print with appropriate color
                            print(f"{Fore.YELLOW}  [!] {severity_color}{finding}{Style.RESET_ALL}")
                    
                    # Ask user if they want to execute this command
                    user_choice = input(f"{Fore.YELLOW}[?] Execute this advanced command? (y/n): {Style.RESET_ALL}").strip().lower()
                    if user_choice != 'y':
                        print(f"{Fore.RED}[*] Command execution skipped.{Style.RESET_ALL}")
                        return False
                    
                    # Execute the advanced command
                    print(f"\n{Fore.GREEN}[+] Executing advanced command: {cmd}{Style.RESET_ALL}")
                    output = run_command(cmd, show_progress=True, save_output=True)
                    
                    # Update context with the new command
                    if output:
                        command_context.update(cmd, cmd_type, output)
                        
                        # Save the analysis to a file for reference
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        advanced_file = os.path.join(RESULTS_DIR, f"advanced_{target.replace('.', '_')}_{cmd_type}_{timestamp}.json")
                        with open(advanced_file, 'w') as f:
                            json.dump(response, f, indent=2)
                    
                    return True
                else:
                    # If JSON parsing failed, try to extract command from the response
                    print(f"{Fore.YELLOW}[*] AI returned non-JSON response. Attempting to extract commands...{Style.RESET_ALL}")
                    success, _ = extract_and_execute_command(response_text, context_type=f"{current_scan_type}_advanced")
                    return success
            
            except Exception as e:
                print(f"{Fore.RED}[-] Error generating advanced command: {str(e)}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Attempting to extract commands from raw response...{Style.RESET_ALL}")
                success, _ = extract_and_execute_command(response_text, context_type=f"{current_scan_type}_advanced")
                return success

        # Handle target setting
        if re.search(r'set\s+t[a]*rget\s+', command.lower()):
            match = re.search(r'set\s+t[a]*rget\s+(.*)', command)
            if match:
                new_target = match.group(1).strip()
                if new_target.lower().startswith("http://"):
                    new_target = new_target[7:]
                elif new_target.lower().startswith("https://"):
                    new_target = new_target[8:]
                target = new_target
                command_context.target = target
                print(f"{Fore.GREEN}[+] Target set to: {target}{Style.RESET_ALL}")
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
                    
                    # Display which AI is being used
                    use_dual = False
                    if DEFAULT_PROVIDER == "dual" and gemini_client:
                        print(f"{Fore.CYAN}[INFO] Querying both OpenRouter and Gemini APIs for enhanced results{Style.RESET_ALL}")
                        use_dual = True
                    elif DEFAULT_PROVIDER == "gemini" and gemini_client:
                        print(f"{Fore.CYAN}[INFO] Querying Gemini API for enhanced results{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.CYAN}[INFO] Querying OpenRouter API for enhanced results{Style.RESET_ALL}")
                    
                    target_info = query_ai(target_prompt, f"Analyze target: {target}", temperature=0.5, use_dual=use_dual)
                    if target_info:
                        print(f"\n{Fore.CYAN}TARGET ANALYSIS:{Style.RESET_ALL}")
                        print(f"{Fore.WHITE}{target_info}{Style.RESET_ALL}\n")
                return True

        # Process normal commands with AI - ensuring rich context
        context = command_context.get_context()
        
        # Build a rich prompt with full context to ensure high-quality AI responses
        prompt = f"""You are a penetration testing AI assistant in a Kali Linux terminal.
        
        Current context:
        - Target: {target if target else "Not set"}
        - Last command type: {context['last_command_type'] if context['last_command_type'] else "None"}
        - Last command: {context['last_command'] if context['last_command'] else "None"}
        
        Recent command history:
        {chr(10).join([f"- {cmd['type']}: {cmd['command']}" for cmd in context['scan_history']])}
        
        USER REQUEST: {command}
        
        Generate a Kali Linux command that fulfills the user's request above. Be thorough and use appropriate tools.
        
        Return ONLY a JSON with the following:
        - "command": The exact command to execute (including all necessary flags/options)
        - "explanation": Brief explanation of what the command does and why it's appropriate
        - "type": Command type (e.g., "nmap", "whois", "gobuster", etc.) for context tracking
        """
        
        # Query AI with the specified provider
        print(f"{Fore.CYAN}[*] Generating command using {DEFAULT_PROVIDER.capitalize()} API...{Style.RESET_ALL}")
        response_text = query_ai(prompt, command)
        
        if response_text:
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
                    cmd = response["command"]
                    cmd_type = response.get("type", "unknown")
                    
                    # Replace target placeholder if needed
                    if target and "<target>" in cmd:
                        cmd = cmd.replace("<target>", target)
                    
                    print(f"{Fore.BLUE}[*] {response.get('explanation', 'Executing command:')}{Style.RESET_ALL}")
                    output = run_command(cmd, show_progress=True, save_output=True)
                    
                    # Update context with the new command
                    if output:
                        command_context.update(cmd, cmd_type, output)
                    
                    return True
                else:
                    # Try fallback to raw command extraction
                    if "``" in response_text:
                        command_match = re.search(r'```(?:bash|sh)?\s*(.*?)\s*```', response_text, re.DOTALL)
                        if command_match:
                            cmd = command_match.group(1).strip().split('\n')[0]  # Get first line only
                            print(f"{Fore.YELLOW}[*] Extracted command from response: {cmd}{Style.RESET_ALL}")
                            output = run_command(cmd, show_progress=True, save_output=True)
                            if output:
                                command_context.update(cmd, "extracted", output)
                            return True
            except json.JSONDecodeError:
                pass
        
        # Try fallback provider if needed
        if GEMINI_AVAILABLE and DEFAULT_PROVIDER != "gemini":
            print(f"{Fore.YELLOW}[!] Trying with Gemini API instead...{Style.RESET_ALL}")
            original_provider = DEFAULT_PROVIDER
            DEFAULT_PROVIDER = "gemini"
            success = attempt_command_with_provider(command, "gemini", [])
            DEFAULT_PROVIDER = original_provider
            return success
        
        return False
    
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Style.RESET_ALL}")
        return False

# Helper function to try executing a command with a specific AI provider
def attempt_command_with_provider(command, provider, tried_providers=None):
    """
    Attempt to generate and execute a command using the specified AI provider
    Returns True if command executed successfully, False otherwise
    """
    global DEFAULT_PROVIDER, target
    
    if tried_providers is None:
        tried_providers = []
    
    # Skip if we've already tried this provider
    if provider in tried_providers:
        return False
    
    # Add to the list of tried providers
    tried_providers.append(provider)
    
    # Temporarily set the provider
    original_provider = DEFAULT_PROVIDER
    DEFAULT_PROVIDER = provider
    
    try:
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
        
        # Query AI with the specified provider
        print(f"{Fore.CYAN}[*] Generating command using {provider.capitalize()} API...{Style.RESET_ALL}")
        response_text = query_ai(prompt, command)
        if not response_text:
            print(f"{Fore.RED}[-] Failed to get response from {provider.capitalize()} API{Style.RESET_ALL}")
            DEFAULT_PROVIDER = original_provider  # Restore original provider
            return False
        
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
                        "explanation": f"Extracted command from {provider.capitalize()} response."
                    }
                else:
                    # Try to find any command-like string in the response
                    lines = response_text.split('\n')
                    for line in lines:
                        if any(tool in line.lower() for tool in ["nmap", "gobuster", "sqlmap", "hydra", "msfconsole"]):
                            response = {
                                "command": line.strip(),
                                "explanation": f"Extracted command from {provider.capitalize()} response."
                            }
                            break
                    else:
                        print(f"{Fore.RED}[-] Could not extract a usable command from {provider.capitalize()} response{Style.RESET_ALL}")
                        DEFAULT_PROVIDER = original_provider  # Restore original provider
                        return False
        
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
                    DEFAULT_PROVIDER = original_provider  # Restore original provider
                    return False
            
            # Execute the command
            print(f"{Fore.GREEN}[+] Executing command from {provider.capitalize()} API: {cmd}{Style.RESET_ALL}")
            output = run_command(cmd, show_progress=True, save_output=True)
            
            # Check if command was successful
            if output is not None:
                DEFAULT_PROVIDER = original_provider  # Restore original provider
                return True
            else:
                print(f"{Fore.RED}[-] Command from {provider.capitalize()} API failed{Style.RESET_ALL}")
                DEFAULT_PROVIDER = original_provider  # Restore original provider
                return False
        else:
            print(f"{Fore.YELLOW}[*] No command to execute from {provider.capitalize()} API{Style.RESET_ALL}")
            DEFAULT_PROVIDER = original_provider  # Restore original provider
            return False
    
    except Exception as e:
        print(f"{Fore.RED}[-] Error with {provider.capitalize()} command generation: {str(e)}{Style.RESET_ALL}")
        DEFAULT_PROVIDER = original_provider  # Restore original provider
        return False

# Main CLI loop
def main():
    print(f"{Fore.MAGENTA}{ASCII_LOGO}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}Version 1.2 - Use this tool responsibly and legally{Style.RESET_ALL}")
    
    # Check API keys first
    if not check_api_keys():
        print(f"{Fore.RED}[!] Cannot continue without working API keys. Please update them in the script.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Tip: You can set your OpenRouter API key as an environment variable:{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    export OPENROUTER_API_KEY=your_key_here{Style.RESET_ALL}")
        sys.exit(1)
    
    # Check if Gemini API is available
    gemini_available_str = ""
    if gemini_client:
        gemini_available_str = f"{Fore.GREEN}AVAILABLE{Style.RESET_ALL}"
    else:
        gemini_available_str = f"{Fore.RED}NOT AVAILABLE{Style.RESET_ALL}"
        if not GEMINI_AVAILABLE:
            print(f"{Fore.YELLOW}[!] To use Gemini API, install the package: pip install google-generativeai{Style.RESET_ALL}")
    
    # Add an initial menu to select the AI provider
    global DEFAULT_PROVIDER
    
    print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║       SELECT YOUR AI PROVIDER(S)              ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╠══════════════════════════════════════════════╣{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║ [1] OpenRouter API (DeepSeek Chat)            ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║     Recommended: Stable & reliable for        ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║     advanced penetration testing tasks        ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╠══════════════════════════════════════════════╣{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║ [2] Google Gemini API [{gemini_available_str}] ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║     Recommended: Great for reconnaissance,    ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║     OSINT, and low-level pentesting           ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╠══════════════════════════════════════════════╣{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║ [3] Dual Mode (Use Both APIs for Best Results)║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║     Recommended: Best overall performance     ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}║     for all types of penetration testing      ║{Style.RESET_ALL}")
    print(f"{Fore.CYAN}╚══════════════════════════════════════════════╝{Style.RESET_ALL}")
    
    # Get user choice
    choice = ""
    while choice not in ["1", "2", "3"]:
        choice = input(f"{Fore.YELLOW}Enter your choice (1-3): {Style.RESET_ALL}")
        if choice == "1":
            if "OpenRouter API key is invalid" not in globals().get("_openrouter_key_status", ""):
                DEFAULT_PROVIDER = "openrouter"
                print(f"{Fore.GREEN}[+] Using OpenRouter API with DeepSeek model{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] OpenRouter API key is invalid. Defaulting to Gemini if available.{Style.RESET_ALL}")
                DEFAULT_PROVIDER = "gemini" if gemini_client else "openrouter"
                if not gemini_client:
                    print(f"{Fore.RED}[-] No working AI providers available. Using OpenRouter but expect errors.{Style.RESET_ALL}")
                choice = ""  # Reset to force another choice
        elif choice == "2":
            if gemini_client:
                DEFAULT_PROVIDER = "gemini"
                print(f"{Fore.GREEN}[+] Using Google Gemini API{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Google Gemini API is not available. Defaulting to OpenRouter API.{Style.RESET_ALL}")
                DEFAULT_PROVIDER = "openrouter"
                choice = ""  # Reset to force another choice
        elif choice == "3":
            if gemini_client:
                DEFAULT_PROVIDER = "dual"
                print(f"{Fore.GREEN}[+] Using Dual Mode (Both APIs for best results){Style.RESET_ALL}")
                if "OpenRouter API key is invalid" in globals().get("_openrouter_key_status", ""):
                    print(f"{Fore.YELLOW}[!] Note: OpenRouter API key is invalid, dual mode will rely primarily on Gemini{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Google Gemini API is not available. Dual mode not possible.{Style.RESET_ALL}")
                DEFAULT_PROVIDER = "openrouter" 
                choice = ""  # Reset to force another choice
    
    print(f"\n{Fore.GREEN}[+] You can change the AI provider anytime with:{Style.RESET_ALL}")
    print(f"{Fore.GREEN}    - 'use openrouter' - Switch to OpenRouter API{Style.RESET_ALL}")
    if gemini_client:
        print(f"{Fore.GREEN}    - 'use gemini' - Switch to Google Gemini API{Style.RESET_ALL}")
        print(f"{Fore.GREEN}    - 'use dual' - Use both APIs together{Style.RESET_ALL}")
    
    # Main loop instructions
    print(f"\n{Fore.BLUE}Type 'exit' to quit, 'stop' to kill running scans, 'help' for assistance.{Style.RESET_ALL}")
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
  use dual                  - Use both AI providers for enhanced results
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

# Function to check if API keys are valid
def check_api_keys():
    """Check if the API keys are valid and working"""
    global openrouter_client, OPENROUTER_API_KEY, DEFAULT_PROVIDER
    
    print(f"{Fore.YELLOW}[*] Checking API keys...{Style.RESET_ALL}")
    globals()["_openrouter_key_status"] = ""  # Reset status
    
    # Get a new OpenRouter API key from environment variable if available
    env_openrouter_key = os.environ.get("OPENROUTER_API_KEY")
    if env_openrouter_key and env_openrouter_key != OPENROUTER_API_KEY:
        print(f"{Fore.GREEN}[+] Found OpenRouter API key in environment variables{Style.RESET_ALL}")
        OPENROUTER_API_KEY = env_openrouter_key
        # Recreate client with new key
        openrouter_client = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=OPENROUTER_API_KEY,
            default_headers={
                "HTTP-Referer": "https://zotak-cli.com",
                "X-Title": "Zotak CLI"
            }
        )
    
    # Check OpenRouter API
    openrouter_working = False
    try:
        # Simple test query to OpenRouter
        completion = openrouter_client.chat.completions.create(
            model=DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "Say hello"}
            ],
            max_tokens=5
        )
        print(f"{Fore.GREEN}[+] OpenRouter API key is valid{Style.RESET_ALL}")
        openrouter_working = True
    except Exception as e:
        error_message = str(e)
        globals()["_openrouter_key_status"] = f"OpenRouter API key is invalid: {error_message}"
        
        if "401" in error_message or "unauthorized" in error_message.lower() or "authentication" in error_message.lower():
            print(f"{Fore.RED}[-] OpenRouter API key is invalid or expired: {error_message}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] You will need to update the OPENROUTER_API_KEY in the script.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Get a new key from: https://openrouter.ai/keys{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Or set it as an environment variable: OPENROUTER_API_KEY=your_key_here{Style.RESET_ALL}")
            
            # Try to fix by updating to a default key (for demo purposes)
            try:
                print(f"{Fore.YELLOW}[*] Attempting to use alternative key configuration...{Style.RESET_ALL}")
                # Try using standard base_url without v1
                alt_client = OpenAI(
                    base_url="https://openrouter.ai/api",
                    api_key=OPENROUTER_API_KEY
                )
                # Test the new configuration with a simple request
                completion = alt_client.chat.completions.create(
                    model=DEFAULT_MODEL,
                    messages=[
                        {"role": "system", "content": "You are a helpful assistant."},
                        {"role": "user", "content": "Say hello"}
                    ],
                    max_tokens=5
                )
                print(f"{Fore.GREEN}[+] Successfully fixed OpenRouter authentication with alternative configuration{Style.RESET_ALL}")
                openrouter_client = alt_client
                openrouter_working = True
                globals()["_openrouter_key_status"] = ""
            except Exception as fix_error:
                print(f"{Fore.RED}[-] Could not fix OpenRouter authentication: {str(fix_error)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Error with OpenRouter API: {error_message}{Style.RESET_ALL}")
    
    # Check if Gemini is available and working
    gemini_working = False
    if gemini_client:
        try:
            # Simple test query to Gemini
            response = gemini_client.generate_content(["You are a helpful assistant.", "Say hello"])
            print(f"{Fore.GREEN}[+] Google Gemini API key is valid{Style.RESET_ALL}")
            gemini_working = True
        except Exception as e:
            print(f"{Fore.RED}[-] Google Gemini API error: {str(e)}{Style.RESET_ALL}")
    
    # Set appropriate default provider based on what's working
    if openrouter_working and DEFAULT_PROVIDER == "openrouter":
        # Keep as is
        pass
    elif gemini_working and not openrouter_working:
        print(f"{Fore.YELLOW}[!] Setting default provider to Gemini since OpenRouter is not working{Style.RESET_ALL}")
        DEFAULT_PROVIDER = "gemini"
    elif openrouter_working and not gemini_working and DEFAULT_PROVIDER == "gemini":
        print(f"{Fore.YELLOW}[!] Setting default provider to OpenRouter since Gemini is not working{Style.RESET_ALL}")
        DEFAULT_PROVIDER = "openrouter"
    elif openrouter_working and gemini_working and DEFAULT_PROVIDER == "dual":
        # Keep dual mode
        pass
    elif not openrouter_working and not gemini_working:
        print(f"{Fore.RED}[-] No working AI providers available. Please fix API keys.{Style.RESET_ALL}")
        return False
    
    return True

# Function to safely extract and execute commands from AI responses
def extract_and_execute_command(response_text, context_type="unknown"):
    """Extract commands from AI response text and ask for user permission before executing"""
    # Try to find commands in code blocks
    command_match = re.search(r'```(?:bash|shell|sh)?\s*(.*?)\s*```', response_text, re.DOTALL)
    if command_match:
        extracted_cmd = command_match.group(1).strip().split('\n')[0]  # Get first line only
        print(f"{Fore.YELLOW}[*] Found command in AI response: {extracted_cmd}{Style.RESET_ALL}")
        user_choice = input(f"{Fore.YELLOW}[?] Execute this command? (y/n): {Style.RESET_ALL}").strip().lower()
        
        if user_choice == 'y':
            print(f"{Fore.GREEN}[+] Executing extracted command: {extracted_cmd}{Style.RESET_ALL}")
            output = run_command(extracted_cmd, show_progress=True, save_output=True)
            if output and command_context:
                command_context.update(extracted_cmd, f"extracted_{context_type}", output)
            return True, output
        else:
            print(f"{Fore.RED}[*] Command execution skipped.{Style.RESET_ALL}")
            return False, None
    
    # If no command found in code blocks, look for commands in plain text
    # This is less reliable, so we're more cautious
    lines = response_text.split('\n')
    potential_commands = []
    
    # Look for lines that might be commands (start with common CLI tools)
    command_starters = ["nmap ", "whatweb ", "gobuster ", "dirb ", "sqlmap ", "hydra ", 
                        "wfuzz ", "nikto ", "whois ", "dig ", "host ", "curl ", "wget "]
    
    for line in lines:
        line = line.strip()
        if any(line.startswith(starter) for starter in command_starters):
            potential_commands.append(line)
    
    if potential_commands:
        print(f"{Fore.YELLOW}[*] Found potential commands in AI response:{Style.RESET_ALL}")
        for i, cmd in enumerate(potential_commands):
            print(f"{Fore.CYAN}[{i+1}] {cmd}{Style.RESET_ALL}")
        
        cmd_choice = input(f"{Fore.YELLOW}[?] Enter command number to execute (or 'n' to skip): {Style.RESET_ALL}").strip().lower()
        
        if cmd_choice.isdigit() and 0 < int(cmd_choice) <= len(potential_commands):
            selected_cmd = potential_commands[int(cmd_choice) - 1]
            print(f"{Fore.GREEN}[+] Executing selected command: {selected_cmd}{Style.RESET_ALL}")
            output = run_command(selected_cmd, show_progress=True, save_output=True)
            if output and command_context:
                command_context.update(selected_cmd, f"extracted_{context_type}", output)
            return True, output
        else:
            print(f"{Fore.RED}[*] Command execution skipped.{Style.RESET_ALL}")
            return False, None
    
    # If no commands found
    print(f"{Fore.RED}[-] No executable commands found in AI response{Style.RESET_ALL}")
    
    # Ask if user wants to see the raw response
    user_choice = input(f"{Fore.YELLOW}[?] Show raw AI response? (y/n): {Style.RESET_ALL}").strip().lower()
    if user_choice == 'y':
        print(f"\n{Fore.GREEN}[+] Raw AI response:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{response_text}{Style.RESET_ALL}")
    
    return False, None

if __name__ == "__main__":
    main()
