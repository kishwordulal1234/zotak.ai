#!/usr/bin/env python3
import os
import sys
import json
import argparse
import datetime
import requests
import subprocess
import time
import re
import shutil
import platform
import threading
import psutil
from datetime import timedelta
from prompt_toolkit import PromptSession
from prompt_toolkit.history import FileHistory
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.styles import Style
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.filters import Condition
from pygments.lexers.markup import MarkdownLexer
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich import box
from colorama import Fore, Style as ColoramaStyle, init
init()  # Initialize colorama
try:
    import google.generativeai as genai
except ImportError:
    genai = None

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

# File paths
HOME_DIR = os.path.expanduser("~")
CONFIG_DIR = os.path.join(HOME_DIR, ".zotakai")
HISTORY_FILE = os.path.join(CONFIG_DIR, "history.txt")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
LOGS_DIR = os.path.join(CONFIG_DIR, "logs")
TOOLS_DIR = os.path.join(CONFIG_DIR, "tools")
CONVERSATION_FILE = os.path.join(CONFIG_DIR, "conversations.json")

# Ensure directories exist
os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(TOOLS_DIR, exist_ok=True)

# Default configuration
DEFAULT_CONFIG = {
    "openrouter_api_key": "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",
    "gemini_api_key": "AIzaSyCpQk4OdjPW0VbYEMtx_EPKNa_f9zXUV40",
    "default_model": "openrouter",
    "ai_provider_mode": "single",  # single or dual
    "openrouter_model": "deepseek/deepseek-chat-v3-0324:free",
    "gemini_model": "gemini-2.0-flash",
    "max_history": 30,
    "auto_execute": True,  # Commands will execute automatically
    "auto_fix": True,
    "auto_install": False,
    "security_tools": ["nmap", "metasploit-framework", "sqlmap", "gobuster", "nikto", "hydra"],
    "system_prompt": "You are a friendly and helpful AI security terminal assistant for penetration testing, network security, and system administration. ALWAYS follow these guidelines: 1) Respond appropriately to casual conversation without suggesting security commands. 2) Only suggest commands when explicitly asked about security tasks. 3) Never make assumptions about network hosts or scans unless specifically mentioned by the user. 4) When suggesting commands, explain what they do and format them with the bash prefix for easy execution. 5) For security-related questions, provide direct answers first before suggesting commands. 6) Only offer to fix errors or install tools when explicitly requested.",
    "theme": "dark",
    "safe_mode": True,  # Prevents potentially destructive commands
    "first_run": True  # Flag to show selection menu on first run
}

# Rich console for formatted output
console = Console()

def display_system_info():
    """Display system information using neofetch if available"""
    # Try to run neofetch
    if shutil.which("neofetch"):
        try:
            # Run neofetch with no color blocks to avoid display issues
            subprocess.run("neofetch --color_blocks off", shell=True)
            return True
        except:
            pass
    
    # If neofetch isn't available or fails
    console.print("[bold yellow]Neofetch not found. Basic system info:[/bold yellow]")
    
    # Print basic system info
    system = platform.system()
    version = platform.version()
    processor = platform.processor()
    
    try:
        username = os.environ.get('USER') or os.environ.get('USERNAME') or 'user'
        hostname = platform.node()
        
        # Get memory information
        mem = psutil.virtual_memory()
        memory = f"{mem.used // (1024*1024)}MiB / {mem.total // (1024*1024)}MiB"
        
        # Get disk information
        disk = psutil.disk_usage('/')
        disk_info = f"{disk.used // (1024*1024*1024)}GB / {disk.total // (1024*1024*1024)}GB ({disk.percent}%)"
        
        print(f"{Fore.GREEN}OS:{ColoramaStyle.RESET_ALL} {system} {version}")
        print(f"{Fore.GREEN}Host:{ColoramaStyle.RESET_ALL} {hostname}")
        print(f"{Fore.GREEN}CPU:{ColoramaStyle.RESET_ALL} {processor}")
        print(f"{Fore.GREEN}Memory:{ColoramaStyle.RESET_ALL} {memory}")
        print(f"{Fore.GREEN}Disk:{ColoramaStyle.RESET_ALL} {disk_info}")
    except Exception as e:
        print(f"{Fore.GREEN}OS:{ColoramaStyle.RESET_ALL} {system} {version}")
        print(f"{Fore.GREEN}Error getting detailed info:{ColoramaStyle.RESET_ALL} {str(e)}")
    
    return False

class ZotakAI:
    def __init__(self):
        self.load_config()
        self.command_log = []
        self.conversation_history = []
        self.load_conversation_history()
        self.package_manager = self.detect_package_manager()
        
        # Set up prompt session with history
        self.session = PromptSession(
            history=FileHistory(HISTORY_FILE),
            lexer=PygmentsLexer(MarkdownLexer),
            style=self.get_style()
        )
        
        # Security tools mapping for quick reference
        self.security_tools_map = {
            "nmap": {"description": "Network scanner", "install_cmd": f"{self.package_manager} install nmap -y"},
            "metasploit-framework": {"description": "Penetration testing framework", "install_cmd": f"{self.package_manager} install metasploit-framework -y"},
            "sqlmap": {"description": "SQL injection scanner", "install_cmd": f"{self.package_manager} install sqlmap -y"},
            "gobuster": {"description": "Directory/file & DNS busting tool", "install_cmd": f"{self.package_manager} install gobuster -y"},
            "nikto": {"description": "Web server scanner", "install_cmd": f"{self.package_manager} install nikto -y"},
            "hydra": {"description": "Password cracking tool", "install_cmd": f"{self.package_manager} install hydra -y"},
            "dirbuster": {"description": "Web directory brute force tool", "install_cmd": f"{self.package_manager} install dirbuster -y"},
            "wireshark": {"description": "Network protocol analyzer", "install_cmd": f"{self.package_manager} install wireshark -y"},
            "aircrack-ng": {"description": "Wireless security tool", "install_cmd": f"{self.package_manager} install aircrack-ng -y"},
            "john": {"description": "Password cracker", "install_cmd": f"{self.package_manager} install john -y"},
            "hashcat": {"description": "Advanced password recovery", "install_cmd": f"{self.package_manager} install hashcat -y"}
        }
        
        # Common error patterns and fixes
        self.common_errors = {
            "command not found": self.handle_command_not_found,
            "permission denied": self.handle_permission_denied,
            "database is not started": self.handle_db_not_started,
            "connection refused": self.handle_connection_refused,
            "Failed to open": self.handle_file_not_found,
            "postgresql": self.handle_postgres_issue,
            "FATAL: database": self.handle_postgres_issue,
            "unknown host": self.handle_unknown_host,
            "no route to host": self.handle_network_issue,
        }
    
    def detect_package_manager(self):
        """Detect the system's package manager"""
        system = platform.system().lower()
        
        if system == "linux":
            # Check for specific distributions
            try:
                with open("/etc/os-release", "r") as f:
                    content = f.read().lower()
                    
                if "kali" in content:
                    return "apt-get"
                elif "ubuntu" in content or "debian" in content:
                    return "apt-get"
                elif "fedora" in content:
                    return "dnf"
                elif "centos" in content or "rhel" in content:
                    return "yum"
                elif "arch" in content:
                    return "pacman -S"
            except:
                pass
            
            # Fallback checks
            if shutil.which("apt-get"):
                return "apt-get"
            elif shutil.which("dnf"):
                return "dnf"
            elif shutil.which("yum"):
                return "yum"
            elif shutil.which("pacman"):
                return "pacman -S"
        
        elif system == "darwin":  # macOS
            if shutil.which("brew"):
                return "brew install"
            
        # Default case
        return "apt-get"  # Most common for security-focused distros
        
    def load_config(self):
        """Load or create configuration file"""
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, 'r') as f:
                    self.config = json.load(f)
                    # Update with any new default config fields
                    for key, value in DEFAULT_CONFIG.items():
                        if key not in self.config:
                            self.config[key] = value
                    
                    # Force first_run flag to True to show selection menu
                    self.config["first_run"] = True
            except json.JSONDecodeError:
                console.print("[bold red]Error loading config. Loading defaults.[/bold red]")
                self.config = DEFAULT_CONFIG.copy()
        else:
            self.config = DEFAULT_CONFIG.copy()
            self.save_config()
            console.print(f"[bold yellow]Created new config file at {CONFIG_FILE}[/bold yellow]")
            console.print("[bold yellow]Please set your API keys with 'config openrouter_api_key YOUR_KEY' and 'config gemini_api_key YOUR_KEY'[/bold yellow]")
    
    def save_config(self):
        """Save current configuration to file"""
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def get_style(self):
        """Get prompt style based on theme"""
        if self.config["theme"] == "dark":
            return Style.from_dict({
                'prompt': 'ansicyan bold',
                'continuation': 'ansiblue',
            })
        else:
            return Style.from_dict({
                'prompt': 'ansigreen bold',
                'continuation': 'ansiblue',
            })
    
    def load_conversation_history(self):
        """Load conversation history from file"""
        if os.path.exists(CONVERSATION_FILE):
            try:
                with open(CONVERSATION_FILE, 'r') as f:
                    data = json.load(f)
                    self.conversation_history = data.get("messages", [])
                    self.command_log = data.get("commands", [])
            except (json.JSONDecodeError, FileNotFoundError):
                self.conversation_history = []
                self.command_log = []
    
    def save_conversation_history(self):
        """Save conversation history to file"""
        with open(CONVERSATION_FILE, 'w') as f:
            json.dump({
                "messages": self.conversation_history[-self.config["max_history"]:],
                "commands": self.command_log[-self.config["max_history"]:]
            }, f, indent=2)
    
    def log_command(self, command, output):
        """Log a command and its output"""
        timestamp = datetime.datetime.now().isoformat()
        self.command_log.append({
            "timestamp": timestamp,
            "command": command,
            "output": output
        })
        
        # Also save to daily log file
        date_str = datetime.datetime.now().strftime("%Y-%m-%d")
        log_file = os.path.join(LOGS_DIR, f"{date_str}.log")
        
        with open(log_file, 'a') as f:
            f.write(f"\n[{timestamp}] COMMAND: {command}\n")
            f.write(f"OUTPUT:\n{output}\n{'-' * 40}\n")
        
        self.save_conversation_history()
    
    def add_to_conversation(self, role, content):
        """Add a message to conversation history"""
        self.conversation_history.append({
            "role": role,
            "content": content
        })
        self.save_conversation_history()
    
    def is_safe_command(self, command):
        """Check if a command is safe to execute automatically"""
        # List of potentially destructive commands to block in safe mode
        unsafe_patterns = [
            r"\brm\s+(-rf?|--recursive)\b",  # Recursive remove
            r"\bmv\s+/\b",                  # Move from root
            r"\brmdir\s+/\b",               # Remove root dir
            r"\bdd\s+.*of=/dev/",           # Raw disk operations
            r"\bmkfs\b",                    # Format filesystem
            r"\bformat\b",                  # Format command
            r"\bshred\b",                   # Secure delete
            r">>/etc/",                      # Append to system config
            r">/etc/",                       # Write to system config
            r"\bsudo\s+rm\b",               # Sudo remove
            r"\bsystemctl\s+(stop|disable)", # Stopping services
            r"\bservice\s+.*\s+stop\b",      # Stopping services
            r"\bchmod\s+-[R\s]*777\b",      # Recursive chmod 777
            r"\bchmod\s+777\b",             # chmod 777
            r"\b(wget|curl)\s+.*\s+\|\s+(\.\s+|bash|sh)\b", # Piping wget/curl to shell
            r"\beval\b",                    # eval command
        ]
        
        if not self.config.get("safe_mode", True):
            return True  # Safe mode disabled, allow any command
            
        for pattern in unsafe_patterns:
            if re.search(pattern, command):
                return False
                
        return True
    
    def execute_command(self, command, show_output=True, auto_fix=True):
        """Execute a shell command and return the output"""
        try:
            if show_output:
                console.print(f"[bold blue]Executing:[/bold blue] {command}")
            
            # Security check for potentially harmful commands
            if not self.is_safe_command(command):
                warning = "⚠️ This command may be potentially destructive. For safety, it requires manual confirmation."
                if show_output:
                    console.print(f"[bold red]{warning}[/bold red]")
                    confirm = input("Do you want to proceed anyway? (y/N): ").lower().strip()
                    if confirm != 'y' and confirm != 'yes':
                        return "Command execution cancelled for safety reasons."
            
            result = subprocess.run(command, shell=True, text=True, capture_output=True)
            
            if result.returncode == 0:
                output = result.stdout
                if show_output:
                    console.print("[bold green]Command completed successfully[/bold green]")
            else:
                output = f"Error (code {result.returncode}):\n{result.stderr}"
                if show_output:
                    console.print(f"[bold red]Command failed with code {result.returncode}[/bold red]")
                
                # Auto-fix mechanism
                if auto_fix and self.config.get("auto_fix", True):
                    fixed = self.attempt_to_fix_error(command, result.stderr)
                    if fixed:
                        output += f"\n\n[Auto-fixed] {fixed}"
            
            self.log_command(command, output)
            return output
        except Exception as e:
            error_msg = f"Failed to execute command: {str(e)}"
            if show_output:
                console.print(f"[bold red]{error_msg}[/bold red]")
            self.log_command(command, error_msg)
            return error_msg
    
    def attempt_to_fix_error(self, failed_command, error_output):
        """Attempt to automatically fix common errors"""
        if not error_output:
            return None
            
        error_output = error_output.lower()
        
        for error_pattern, handler in self.common_errors.items():
            if error_pattern in error_output:
                return handler(failed_command, error_output)
                
        return None
    
    def handle_command_not_found(self, command, error_output):
        """Handle 'command not found' errors by installing missing tools"""
        # Extract the command name that wasn't found
        match = re.search(r"command not found:?\s*([a-zA-Z0-9_-]+)", error_output)
        if not match:
            return None
            
        missing_tool = match.group(1).strip()
        
        # Try to find the tool in our known security tools
        if missing_tool in self.security_tools_map:
            tool_info = self.security_tools_map[missing_tool]
            install_cmd = tool_info["install_cmd"]
            
            if self.config.get("auto_install", True):
                console.print(f"[bold yellow]Tool '{missing_tool}' not found. Attempting to install...[/bold yellow]")
                
                # Update package lists first (for apt-based systems)
                if self.package_manager.startswith("apt"):
                    self.execute_command("sudo apt update", show_output=True, auto_fix=False)
                
                # Install the missing tool
                result = self.execute_command(f"sudo {install_cmd}", show_output=True, auto_fix=False)
                
                if "installed" in result.lower() or "complete" in result.lower():
                    # Try running the original command again
                    console.print(f"[bold green]Installation successful! Retrying original command.[/bold green]")
                    self.execute_command(command, show_output=True, auto_fix=False)
                    return f"Installed missing tool '{missing_tool}' and retried command."
                else:
                    return f"Attempted to install missing tool '{missing_tool}' but installation may have failed."
        else:
            # Generic package name guess
            if self.config.get("auto_install", True):
                console.print(f"[bold yellow]Command '{missing_tool}' not found. Attempting to install as package...[/bold yellow]")
                
                # Try to install the package with the same name as the command
                result = self.execute_command(f"sudo {self.package_manager} install {missing_tool} -y", show_output=True, auto_fix=False)
                
                if "installed" in result.lower() or "complete" in result.lower():
                    # Try running the original command again
                    console.print(f"[bold green]Installation successful! Retrying original command.[/bold green]")
                    self.execute_command(command, show_output=True, auto_fix=False)
                    return f"Installed missing package '{missing_tool}' and retried command."
        
        return None
    
    def handle_permission_denied(self, command, error_output):
        """Handle permission denied errors by suggesting sudo"""
        if not command.startswith("sudo "):
            console.print("[bold yellow]Permission denied. Retrying with sudo...[/bold yellow]")
            result = self.execute_command(f"sudo {command}", show_output=True, auto_fix=False)
            return f"Retried command with sudo privileges."
        return None
    
    def handle_db_not_started(self, command, error_output):
        """Handle database not started errors, especially for Metasploit"""
        if "metasploit" in command.lower() or "msfconsole" in command.lower():
            console.print("[bold yellow]Metasploit database not started. Starting PostgreSQL...[/bold yellow]")
            self.execute_command("sudo service postgresql start", show_output=True, auto_fix=False)
            time.sleep(2)  # Give PostgreSQL time to start
            self.execute_command("sudo msfdb init", show_output=True, auto_fix=False)
            time.sleep(1)
            console.print("[bold green]Database started. Retrying original command...[/bold green]")
            self.execute_command(command, show_output=True, auto_fix=False)
            return "Started PostgreSQL database for Metasploit and retried command."
        return None
    
    def handle_postgres_issue(self, command, error_output):
        """Handle PostgreSQL related issues"""
        if "metasploit" in command.lower() or "msf" in command.lower() or "postgres" in command.lower():
            console.print("[bold yellow]PostgreSQL issue detected. Attempting to fix...[/bold yellow]")
            
            # Try several common fixes
            self.execute_command("sudo service postgresql restart", show_output=False, auto_fix=False)
            time.sleep(2)
            self.execute_command("sudo msfdb reinit", show_output=False, auto_fix=False)
            time.sleep(1)
            
            console.print("[bold green]PostgreSQL restarted. Retrying original command...[/bold green]")
            self.execute_command(command, show_output=True, auto_fix=False)
            return "Restarted PostgreSQL and reinitialized the Metasploit database."
        return None
    
    def handle_connection_refused(self, command, error_output):
        """Handle connection refused errors"""
        # Check if it's a service that needs to be started
        if "http" in command.lower() or "web" in command.lower():
            console.print("[bold yellow]Connection refused. The web service might be down.[/bold yellow]")
            return "The target web service appears to be down or unreachable."
        
        if "ssh" in command.lower():
            console.print("[bold yellow]SSH connection refused. The SSH service might not be running on the target.[/bold yellow]")
            return "The target SSH service appears to be down or unreachable."
            
        return "Connection refused. The target service might not be running or reachable."
    
    def handle_file_not_found(self, command, error_output):
        """Handle file not found errors"""
        # Extract filename if possible
        match = re.search(r"failed to open\s+[\"']?([^\"']+)[\"']?", error_output, re.IGNORECASE)
        if match:
            filename = match.group(1)
            console.print(f"[bold yellow]File not found: {filename}[/bold yellow]")
            return f"The file '{filename}' was not found. Please check the path and filename."
        
        return "A required file was not found. Please check the path and filename."
    
    def handle_unknown_host(self, command, error_output):
        """Handle unknown host errors"""
        # Try to extract the hostname
        match = re.search(r"unknown host\s+([^\s]+)", error_output, re.IGNORECASE)
        if match:
            hostname = match.group(1)
            console.print(f"[bold yellow]Unknown host: {hostname}[/bold yellow]")
            return f"The hostname '{hostname}' could not be resolved. Check for typos or network connectivity."
        
        return "The hostname could not be resolved. Check for typos or network connectivity."
    
    def handle_network_issue(self, command, error_output):
        """Handle network connectivity issues"""
        console.print("[bold yellow]Network connectivity issue detected.[/bold yellow]")
        
        # Check internet connectivity
        ping_result = self.execute_command("ping -c 1 8.8.8.8", show_output=False, auto_fix=False)
        
        if "1 received" in ping_result:
            return "There's internet connectivity, but the specific host is unreachable."
        else:
            return "There appears to be no internet connectivity. Check your network connection."
    
    def check_and_install_security_tools(self):
        """Check for essential security tools and install missing ones"""
        console.print("[bold blue]Checking for essential security tools...[/bold blue]")
        
        missing_tools = []
        for tool in self.config.get("security_tools", []):
            # Check if tool is in path
            if not shutil.which(tool.split('-')[0]):  # Use first part of name (e.g., metasploit-framework -> metasploit)
                if tool in self.security_tools_map:
                    missing_tools.append(tool)
        
        if missing_tools:
            console.print(f"[bold yellow]Missing security tools: {', '.join(missing_tools)}[/bold yellow]")
            
            if self.config.get("auto_install", True):
                console.print("[bold green]Installing missing tools...[/bold green]")
                
                # Update package lists first (for apt-based systems)
                if self.package_manager.startswith("apt"):
                    self.execute_command("sudo apt update", show_output=True, auto_fix=False)
                
                for tool in missing_tools:
                    if tool in self.security_tools_map:
                        console.print(f"[bold blue]Installing {tool}...[/bold blue]")
                        install_cmd = self.security_tools_map[tool]["install_cmd"]
                        self.execute_command(f"sudo {install_cmd}", show_output=True, auto_fix=False)
                
                console.print("[bold green]Security tools installation completed![/bold green]")
            else:
                console.print("[bold yellow]Auto-install is disabled. Use '!tools install' to install missing tools.[/bold yellow]")
        else:
            console.print("[bold green]All essential security tools are installed.[/bold green]")
    
    def call_openrouter(self, prompt):
        """Call OpenRouter API with the given prompt"""
        if not self.config["openrouter_api_key"]:
            return "OpenRouter API key not set. Use 'config openrouter_api_key YOUR_KEY' to set it."
        
        headers = {
            "Authorization": f"Bearer {self.config['openrouter_api_key']}",
            "Content-Type": "application/json"
        }
        
        # Start with a clean system message - this is the core instruction that will always be included
        system_message = {
            "role": "system", 
            "content": self.config["system_prompt"] + "\n\nIMPORTANT: After a history clear, start completely fresh with no assumptions about previous actions or conversations."
        }
        
        messages = [system_message]
        
        # Only add tool and command context if we have conversation history
        # This ensures a completely fresh start when history is cleared
        if self.conversation_history:
            # Add details about available tools
            tools_info = "Available security tools: "
            tools_info += ", ".join([f"{tool} ({self.security_tools_map.get(tool, {}).get('description', 'N/A')})" 
                                  for tool in self.config.get("security_tools", [])])
            
            # Add recent command history to context only if we have command logs
            recent_cmds = ""
            if self.command_log:
                recent_cmds = "Recent commands and outputs:\n"
                for entry in self.command_log[-3:]:  # Last 3 commands only
                    cmd = entry["command"]
                    output = entry["output"]
                    # Truncate very long outputs
                    if len(output) > 1000:
                        output = output[:1000] + "... [output truncated]"
                    recent_cmds += f"Command: {cmd}\nOutput: {output}\n\n"
            
            # Add system context before the actual conversation
            if self.command_log:  # Only add if we have commands to report
                context_message = {
                    "role": "system", 
                    "content": f"Context information (only if relevant to the current query):\n{tools_info}\n\n{recent_cmds}"
                }
                messages.append(context_message)
                
            # Add conversation history
            for msg in self.conversation_history[-self.config["max_history"]:]:
                messages.append(msg)
        
        # Add the current prompt
        messages.append({"role": "user", "content": prompt})
        
        data = {
            "model": self.config["openrouter_model"],
            "messages": messages
        }
        
        try:
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                json=data
            )
            
            if response.status_code == 200:
                result = response.json()
                if "choices" in result and len(result["choices"]) > 0:
                    return result["choices"][0]["message"]["content"]
                else:
                    return "No response content received from OpenRouter."
            else:
                return f"API Error ({response.status_code}): {response.text}"
        
        except Exception as e:
            return f"Error calling OpenRouter API: {str(e)}"
    
    def call_gemini(self, prompt):
        """Call Gemini API with the given prompt"""
        if not self.config["gemini_api_key"]:
            return "Gemini API key not set. Use 'config gemini_api_key YOUR_KEY' to set it."
        
        if not genai:
            return "Google Generative AI module not installed. Install with: pip install google-generativeai"
            
        try:
            genai.configure(api_key=self.config["gemini_api_key"])
            model = genai.GenerativeModel(self.config["gemini_model"])
            
            # Get system prompt
            system_prompt = self.config["system_prompt"]
            
            # Start with basic context
            full_context = f"You are a security assistant. {system_prompt}"
            
            # Only add detailed context if we have conversation history
            # This ensures a fresh start when history is cleared
            if self.conversation_history:
                # Add details about available tools
                tools_info = "Available security tools: "
                tools_info += ", ".join([f"{tool} ({self.security_tools_map.get(tool, {}).get('description', 'N/A')})" 
                                    for tool in self.config.get("security_tools", [])])
                full_context += f"\n\n{tools_info}"
                
                # Add recent command history to context only if we have command logs
                if self.command_log:
                    recent_cmds = "\n\nRecent commands and outputs:\n"
                    for entry in self.command_log[-3:]:  # Last 3 commands only
                        cmd = entry["command"]
                        output = entry["output"]
                        # Truncate very long outputs
                        if len(output) > 1000:
                            output = output[:1000] + "... [output truncated]"
                        recent_cmds += f"Command: {cmd}\nOutput: {output}\n\n"
                    full_context += recent_cmds
            
            # Add conversation context if we have history
            history_context = ""
            if self.conversation_history:
                history_context = "\n\nConversation history:\n"
                for msg in self.conversation_history[-self.config["max_history"]:]:
                    history_context += f"{msg['role']}: {msg['content']}\n"
                full_context += history_context
            
            # Add the current prompt
            full_context += f"\n\nThe user's next message is: {prompt}"
            
            # Just use the simple generate_content method instead of chat
            response = model.generate_content(full_context)
            
            return response.text
            
        except Exception as e:
            return f"Error calling Gemini API: {str(e)}"
    
    def process_special_commands(self, user_input):
        """Process special commands with ! prefix"""
        # Exit command
        if user_input in ["!exit", "!quit"]:
            console.print("[bold green]Goodbye![/bold green]")
            sys.exit(0)
        
        # Clear screen
        elif user_input == "!clear":
            os.system('cls' if os.name == 'nt' else 'clear')
            return True
        
        # Show help
        elif user_input == "!help":
            self.show_help()
            return True
        
        # Show command history
        elif user_input == "!history":
            self.show_history()
            return True
        
        # Show AI provider selection menu
        elif user_input == "!select":
            self.show_ai_provider_menu()
            return True
        
        # Config commands
        elif user_input.startswith("!config "):
            self.handle_config(user_input[8:])
            return True
        
        # Auto-execute mode toggle
        elif user_input == "!autoexec on":
            self.config["auto_execute"] = True
            self.save_config()
            console.print("[bold green]Auto-execute mode enabled[/bold green]")
            return True
            
        elif user_input == "!autoexec off":
            self.config["auto_execute"] = False
            self.save_config()
            console.print("[bold green]Auto-execute mode disabled[/bold green]")
            return True
            
        # Auto-fix mode toggle
        elif user_input == "!autofix on":
            self.config["auto_fix"] = True
            self.save_config()
            console.print("[bold green]Auto-fix mode enabled[/bold green]")
            return True
            
        elif user_input == "!autofix off":
            self.config["auto_fix"] = False
            self.save_config()
            console.print("[bold green]Auto-fix mode disabled[/bold green]")
            return True
            
        # Auto-install mode toggle
        elif user_input == "!autoinstall on":
            self.config["auto_install"] = True
            self.save_config()
            console.print("[bold green]Auto-install mode enabled[/bold green]")
            return True
            
        elif user_input == "!autoinstall off":
            self.config["auto_install"] = False
            self.save_config()
            console.print("[bold green]Auto-install mode disabled[/bold green]")
            return True
            
        # Safe mode toggle
        elif user_input == "!safe on":
            self.config["safe_mode"] = True
            self.save_config()
            console.print("[bold green]Safe mode enabled - potentially destructive commands require confirmation[/bold green]")
            return True
            
        elif user_input == "!safe off":
            self.config["safe_mode"] = False
            self.save_config()
            console.print("[bold yellow]Safe mode disabled - potentially destructive commands can run without confirmation[/bold yellow]")
            console.print("[bold red]⚠️  Use with caution! ⚠️[/bold red]")
            return True
            
        # Tools management
        elif user_input == "!tools list":
            self.list_security_tools()
            return True
            
        elif user_input == "!tools install":
            self.check_and_install_security_tools()
            return True
            
        # Model selection
        elif user_input == "!model openrouter":
            self.config["ai_provider_mode"] = "single"
            self.config["default_model"] = "openrouter"
            self.save_config()
            console.print(f"[bold green]Default model set to OpenRouter ({self.config['openrouter_model']})[/bold green]")
            return True
            
        elif user_input == "!model gemini":
            self.config["ai_provider_mode"] = "single"
            self.config["default_model"] = "gemini"
            self.save_config()
            console.print("[bold green]Default model set to Gemini Pro[/bold green]")
            return True
            
        elif user_input == "!model dual":
            self.config["ai_provider_mode"] = "dual"
            self.save_config()
            console.print("[bold green]AI provider mode set to dual (using both OpenRouter and Gemini)[/bold green]")
            return True
            
        elif user_input == "!model select":
            self.show_ai_provider_menu()
            return True
            
        # Theme selection
        elif user_input == "!theme dark":
            self.config["theme"] = "dark"
            self.save_config()
            self.session.style = self.get_style()
            console.print("[bold green]Theme set to dark[/bold green]")
            return True
            
        elif user_input == "!theme light":
            self.config["theme"] = "light"
            self.save_config()
            self.session.style = self.get_style()
            console.print("[bold green]Theme set to light[/bold green]")
            return True
            
        # Clear conversation history
        elif user_input == "!clear history":
            # Clear conversation history
            self.conversation_history = []
            # Clear command log
            self.command_log = []
            # Save cleared state
            self.save_conversation_history()
            # Delete the conversation file to ensure a fresh start
            try:
                if os.path.exists(CONVERSATION_FILE):
                    os.remove(CONVERSATION_FILE)
            except:
                pass
            console.print("[bold green]Conversation history and context completely cleared[/bold green]")
            return True
            
        # Reset config to defaults
        elif user_input == "!reset config":
            confirm = input("Are you sure you want to reset configuration to defaults? (y/N): ").lower().strip()
            if confirm == 'y' or confirm == 'yes':
                self.config = DEFAULT_CONFIG.copy()
                self.save_config()
                console.print("[bold green]Configuration reset to defaults[/bold green]")
            else:
                console.print("[bold yellow]Configuration reset cancelled[/bold yellow]")
            return True
            
        # Complete restart
        elif user_input == "!restart":
            # Clear all history
            self.conversation_history = []
            self.command_log = []
            self.save_conversation_history()
            # Delete the conversation file
            try:
                if os.path.exists(CONVERSATION_FILE):
                    os.remove(CONVERSATION_FILE)
            except:
                pass
            # Clear the screen and show welcome message
            os.system('cls' if os.name == 'nt' else 'clear')
            
            # Display system information using neofetch
            display_system_info()
            
            console.print(Panel(
                "[bold blue]ZotakAI Security Assistant[/bold blue]\n"
                "Type [bold green]!help[/bold green] for available commands or start chatting about security tasks.",
                border_style="blue"
            ))
            console.print("[bold green]Session restarted with fresh context[/bold green]")
            return True
        
        # Command wasn't a special command
        return False
    
    def handle_config(self, config_input):
        """Handle config command"""
        parts = config_input.strip().split(' ', 1)
        if len(parts) < 2:
            # List current config
            console.print("[bold blue]Current Configuration:[/bold blue]")
            # Don't print API keys for security
            safe_config = self.config.copy()
            if "openrouter_api_key" in safe_config and safe_config["openrouter_api_key"]:
                safe_config["openrouter_api_key"] = "********" + safe_config["openrouter_api_key"][-4:]
            if "gemini_api_key" in safe_config and safe_config["gemini_api_key"]:
                safe_config["gemini_api_key"] = "********" + safe_config["gemini_api_key"][-4:]
            
            for key, value in safe_config.items():
                console.print(f"  [cyan]{key}[/cyan]: {value}")
            return
            
        key, value = parts
        
        # Validate config key
        if key not in DEFAULT_CONFIG:
            console.print(f"[bold red]Unknown configuration key: {key}[/bold red]")
            console.print(f"[bold yellow]Valid keys: {', '.join(DEFAULT_CONFIG.keys())}[/bold yellow]")
            return
            
        # Handle specific types
        if key == "max_history":
            try:
                value = int(value)
            except ValueError:
                console.print("[bold red]max_history must be an integer[/bold red]")
                return
                
        elif key in ["auto_execute", "auto_fix", "auto_install", "safe_mode"]:
            value = value.lower() in ["true", "yes", "on", "1"]
            
        # Update config
        self.config[key] = value
        self.save_config()
        console.print(f"[bold green]Updated {key} to {value}[/bold green]")
    
    def show_help(self):
        """Display help information"""
        console.print(Panel(
            "[bold]ZotakAI Security Assistant[/bold]\n\n"
            "A terminal-based AI security assistant for penetration testing and security tasks.\n\n"
            "[bold cyan]Special Commands:[/bold cyan]\n"
            "  [green]!help[/green] - Show this help\n"
            "  [green]!exit[/green] or [green]!quit[/green] - Exit the program\n"
            "  [green]!clear[/green] - Clear the screen\n"
            "  [green]!history[/green] - Show command execution history\n"
            "  [green]!select[/green] - Show AI provider selection menu\n"
            "  [green]!config[/green] - Show configuration\n"
            "  [green]!config[/green] <key> <value> - Set configuration\n"
            "  [green]!autoexec[/green] on|off - Toggle auto-execution mode\n"
            "  [green]!autofix[/green] on|off - Toggle auto-fix mode\n"
            "  [green]!autoinstall[/green] on|off - Toggle auto-installation mode\n"
            "  [green]!safe[/green] on|off - Toggle safety mode for potentially destructive commands\n"
            "  [green]!tools[/green] list - List security tools\n"
            "  [green]!tools[/green] install - Check and install missing security tools\n"
            "  [green]!model[/green] openrouter - Use only OpenRouter API\n"
            "  [green]!model[/green] gemini - Use only Gemini API\n"
            "  [green]!model[/green] dual - Use both OpenRouter and Gemini APIs\n"
            "  [green]!model[/green] select - Show AI provider selection menu\n"
            "  [green]!theme[/green] dark|light - Set UI theme\n"
            "  [green]!clear history[/green] - Clear conversation history without restarting\n"
            "  [green]!restart[/green] - Completely restart session with fresh context\n"
            "  [green]!reset config[/green] - Reset configuration to defaults\n\n"
            "[bold cyan]Hints:[/bold cyan]\n"
            "- Ask questions about security techniques, tools, or commands\n"
            "- Request penetration testing strategies for specific scenarios\n"
            "- Ask for help with interpreting results from security tools\n"
            "- Use '!!' to execute the suggested command automatically\n"
            "- Prefix with ! to run shell commands directly\n"
            "- If the AI is referring to past conversations that didn't happen, use [green]!restart[/green]\n",
            title="ZotakAI Help",
            border_style="blue",
            box=box.ROUNDED
        ))
    
    def show_history(self):
        """Display command execution history"""
        if not self.command_log:
            console.print("[bold yellow]No command history available[/bold yellow]")
            return
            
        console.print("[bold blue]Command History:[/bold blue]")
        for i, entry in enumerate(self.command_log[-15:], 1):  # Show last 15 commands
            timestamp = datetime.datetime.fromisoformat(entry["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
            cmd = entry["command"]
            
            # Truncate very long outputs
            output = entry["output"]
            if len(output) > 200:
                output = output[:200] + "... [output truncated]"
                
            console.print(f"[bold cyan]{i}. {timestamp}[/bold cyan]")
            console.print(f"[green]$ {cmd}[/green]")
            console.print(f"{output}\n")
    
    def list_security_tools(self):
        """List available security tools"""
        console.print("[bold blue]Security Tools:[/bold blue]")
        
        # Check which tools are installed
        installed_tools = []
        missing_tools = []
        
        for tool in self.config.get("security_tools", []):
            tool_cmd = tool.split("-")[0]  # Use first part of name (e.g., metasploit-framework -> metasploit)
            if shutil.which(tool_cmd):
                installed_tools.append(tool)
            else:
                missing_tools.append(tool)
        
        # Show installed tools
        if installed_tools:
            console.print("[bold green]Installed:[/bold green]")
            for tool in installed_tools:
                description = self.security_tools_map.get(tool, {}).get("description", "")
                console.print(f"  [green]✓ {tool}[/green] - {description}")
        
        # Show missing tools
        if missing_tools:
            console.print("[bold yellow]Not Installed:[/bold yellow]")
            for tool in missing_tools:
                description = self.security_tools_map.get(tool, {}).get("description", "")
                console.print(f"  [yellow]✗ {tool}[/yellow] - {description}")
            
            console.print("\n[bold yellow]Use '!tools install' to install missing tools[/bold yellow]")
        
        # Show additional available tools
        additional_tools = [tool for tool in self.security_tools_map if tool not in self.config["security_tools"]]
        if additional_tools:
            console.print("\n[bold blue]Additional Available Tools:[/bold blue]")
            for tool in additional_tools:
                description = self.security_tools_map.get(tool, {}).get("description", "")
                console.print(f"  [blue]· {tool}[/blue] - {description}")
    
    def detect_command_pattern(self, output):
        """Detect command suggestions in AI output and highlight them"""
        # First, look for bash prefixed commands which are most likely intended to run
        bash_pattern = r'bash\s+([^\n]+)'
        bash_matches = re.finditer(bash_pattern, output)
        
        commands = []
        for match in bash_matches:
            cmd = match.group(1).strip()
            if cmd and not re.search(r'<[^>]+>', cmd):  # Skip commands with placeholders
                commands.append(cmd)
        
        # If no bash commands found, look for other command patterns
        if not commands:
            # Look for code blocks or command line prefixes
            command_pattern = r'(?:`([^`]+)`|\$\s+([^\n]+))'
            matches = re.finditer(command_pattern, output)
            
            for match in matches:
                cmd = match.group(1) if match.group(1) else match.group(2)
                cmd = cmd.strip()
                
                # Filter out non-commands
                if (cmd and 
                    not cmd.startswith("!") and 
                    not cmd.startswith("#") and
                    "install" not in cmd.lower() and
                    "<" not in cmd and ">" not in cmd and
                    "{" not in cmd and "}" not in cmd and
                    "example.com" not in cmd and
                    len(cmd.split()) > 1):
                    
                    cmd = cmd.split('#')[0].strip()  # Remove comments
                    if cmd:
                        commands.append(cmd)
        
        return commands
    
    def show_ai_provider_menu(self):
        """Display the AI provider selection menu"""
        # Check if Gemini API is available
        gemini_available = genai is not None and self.config["gemini_api_key"]
        gemini_available_str = "AVAILABLE" if gemini_available else "NOT AVAILABLE"
        
        # Display colorful ASCII art menu - don't show the logo again
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════╗{ColoramaStyle.RESET_ALL}")
        print(f"{Fore.CYAN}║       SELECT YOUR AI PROVIDER(S)              ║{ColoramaStyle.RESET_ALL}")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════╣{ColoramaStyle.RESET_ALL}")
        print(f"{Fore.CYAN}║ [1] OpenRouter API (DeepSeek Chat)            ║{ColoramaStyle.RESET_ALL}")
        print(f"{Fore.CYAN}║     Recommended: Stable & reliable for        ║{ColoramaStyle.RESET_ALL}")
        print(f"{Fore.CYAN}║     advanced penetration testing tasks        ║{ColoramaStyle.RESET_ALL}")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════╣{ColoramaStyle.RESET_ALL}")
        print(f"{Fore.CYAN}║ [2] Google Gemini API [{gemini_available_str}] ║{ColoramaStyle.RESET_ALL}")
        print(f"{Fore.CYAN}║     Recommended: Great for reconnaissance,    ║{ColoramaStyle.RESET_ALL}")
        print(f"{Fore.CYAN}║     OSINT, and low-level pentesting           ║{ColoramaStyle.RESET_ALL}")
        print(f"{Fore.CYAN}╠══════════════════════════════════════════════╣{ColoramaStyle.RESET_ALL}")
        print(f"{Fore.CYAN}║ [3] Dual Mode (Use Both APIs for Best Results)║{ColoramaStyle.RESET_ALL}")
        print(f"{Fore.CYAN}║     Recommended: Best overall performance     ║{ColoramaStyle.RESET_ALL}")
        print(f"{Fore.CYAN}║     for all types of penetration testing      ║{ColoramaStyle.RESET_ALL}")
        print(f"{Fore.CYAN}╚══════════════════════════════════════════════╝{ColoramaStyle.RESET_ALL}")
        
        try:
            choice = input(f"{Fore.GREEN}Enter your choice (1-3): {ColoramaStyle.RESET_ALL}").strip()
            
            if choice == "1":
                self.config["ai_provider_mode"] = "single"
                self.config["default_model"] = "openrouter"
                print(f"{Fore.GREEN}Using OpenRouter API with {self.config['openrouter_model']}{ColoramaStyle.RESET_ALL}")
            elif choice == "2":
                if not gemini_available:
                    print(f"{Fore.RED}Gemini API is not available. Please set up the API key first.{ColoramaStyle.RESET_ALL}")
                    return self.show_ai_provider_menu()  # Show menu again
                self.config["ai_provider_mode"] = "single"
                self.config["default_model"] = "gemini"
                print(f"{Fore.GREEN}Using Google Gemini API with {self.config['gemini_model']}{ColoramaStyle.RESET_ALL}")
            elif choice == "3":
                if not gemini_available:
                    print(f"{Fore.RED}Gemini API is not available. Dual mode requires both APIs.{ColoramaStyle.RESET_ALL}")
                    return self.show_ai_provider_menu()  # Show menu again
                self.config["ai_provider_mode"] = "dual"
                print(f"{Fore.GREEN}Using Dual Mode with both OpenRouter and Gemini APIs{ColoramaStyle.RESET_ALL}")
            else:
                print(f"{Fore.RED}Invalid choice. Please enter 1, 2, or 3.{ColoramaStyle.RESET_ALL}")
                return self.show_ai_provider_menu()  # Show menu again
            
            # Set first_run to False
            self.config["first_run"] = False
            self.config["auto_execute"] = True  # Ensure commands auto-execute
            self.save_config()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Selection cancelled. Using default settings.{ColoramaStyle.RESET_ALL}")
            return
    
    def run(self):
        """Main loop for the terminal AI"""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # Display ASCII logo with color
        print(f"{Fore.CYAN}{ASCII_LOGO}{ColoramaStyle.RESET_ALL}")
        
        # Display system information in neofetch style
        display_system_info()
        
        console.print(Panel(
            "[bold blue]ZotakAI Security Assistant[/bold blue]\n"
            "Type [bold green]!help[/bold green] for available commands or start chatting about security tasks.",
            border_style="blue"
        ))
        
        # Show AI provider selection menu on first run
        if self.config.get("first_run", True):
            print(f"\n{Fore.YELLOW}╔════════════════════════════════════════════════════════════╗{ColoramaStyle.RESET_ALL}")
            print(f"{Fore.YELLOW}║  PLEASE SELECT YOUR AI PROVIDER BEFORE CONTINUING          ║{ColoramaStyle.RESET_ALL}")
            print(f"{Fore.YELLOW}╚════════════════════════════════════════════════════════════╝{ColoramaStyle.RESET_ALL}")
            self.show_ai_provider_menu()
        
        # Display a single message about command execution mode
        print(f"{Fore.GREEN}Auto-execution of commands is ENABLED. Commands will run automatically.{ColoramaStyle.RESET_ALL}")
        
        # Force auto-execute to be true regardless of settings
        self.config["auto_execute"] = True
        self.save_config()
        
        # No automatic tool installation at startup - use '!tools install' command instead
        
        while True:
            try:
                # Get user input with fancy prompt
                user_input = self.session.prompt(
                    HTML("<ansigreen>zotak</ansigreen><ansiblue>AI</ansiblue> > ")
                )
                
                # Skip empty input
                if not user_input.strip():
                    continue
                
                # Handle direct shell command
                if user_input.startswith("!") and not user_input.startswith("!!"):
                    if self.process_special_commands(user_input):
                        continue
                        
                    # Execute shell command (removing the ! prefix)
                    shell_cmd = user_input[1:]
                    output = self.execute_command(shell_cmd)
                    
                    # Display output with syntax highlighting for recognized formats
                    if output.strip().startswith("{") and output.strip().endswith("}"):
                        try:
                            # Try to parse as JSON
                            json_obj = json.loads(output)
                            console.print(Syntax(json.dumps(json_obj, indent=2), "json"))
                        except:
                            console.print(output)
                    else:
                        console.print(output)
                        
                    continue
                
                # Handle auto-execution of last suggested command
                if user_input.startswith("!!"):
                    if not self.command_log:
                        console.print("[bold red]No command history available[/bold red]")
                        continue
                        
                    if len(user_input) > 2:
                        # Execute specific command from history (!1, !2, etc.)
                        try:
                            idx = int(user_input[2:]) - 1
                            if 0 <= idx < len(self.command_log):
                                cmd = self.command_log[idx]["command"]
                                console.print(f"[bold blue]Executing from history:[/bold blue] {cmd}")
                                output = self.execute_command(cmd)
                                console.print(output)
                            else:
                                console.print(f"[bold red]Invalid history index: {idx+1}[/bold red]")
                        except ValueError:
                            console.print(f"[bold red]Invalid history index: {user_input[2:]}[/bold red]")
                    else:
                        # Execute last command
                        last_cmd = self.command_log[-1]["command"]
                        console.print(f"[bold blue]Executing last command:[/bold blue] {last_cmd}")
                        output = self.execute_command(last_cmd)
                        console.print(output)
                        
                    continue
                
                # Add user message to conversation history
                self.add_to_conversation("user", user_input)
                
                # Get response from AI based on provider mode
                console.print("[bold blue]Thinking...[/bold blue]")
                
                if self.config["ai_provider_mode"] == "dual":
                    # Get responses from both models
                    openrouter_response = self.call_openrouter(user_input)
                    gemini_response = self.call_gemini(user_input)
                    
                    # Combine responses
                    response = f"OpenRouter Response:\n{openrouter_response}\n\nGemini Response:\n{gemini_response}"
                else:
                    # Use single model based on default_model
                    if self.config["default_model"] == "openrouter":
                        response = self.call_openrouter(user_input)
                    else:  # gemini
                        response = self.call_gemini(user_input)
                
                # Format and display the response
                formatted_response = response.replace("```", "")  # Remove code blocks for better rich display
                
                # Check for command suggestions in the response
                suggested_commands = self.detect_command_pattern(response)
                
                # Add to conversation history
                self.add_to_conversation("assistant", response)
                
                # Display the response
                console.print(Panel(
                    Markdown(formatted_response),
                    border_style="green",
                    title="AI Response",
                    title_align="left"
                ))
                
                # Handle auto-execution of suggested commands
                if suggested_commands and len(suggested_commands) > 0:
                    # Show detected commands
                    console.print(Panel(
                        "\n".join([f"[bold blue]{i}.[/bold blue] [green]{cmd}[/green]" for i, cmd in enumerate(suggested_commands, 1)]),
                        title="[bold yellow]Detected Commands[/bold yellow]",
                        border_style="yellow",
                        expand=False
                    ))
                    
                    # Always execute the first command - no confirmation needed
                    first_cmd = suggested_commands[0]
                    console.print(f"[bold blue]Auto-executing command:[/bold blue] {first_cmd}")
                    output = self.execute_command(first_cmd)
                    console.print(output)
                
            except KeyboardInterrupt:
                # Handle Ctrl+C
                console.print("\n[bold yellow]Use !exit to quit[/bold yellow]")
                continue
                
            except Exception as e:
                console.print(f"[bold red]Error: {str(e)}[/bold red]")
                continue

def main():
    parser = argparse.ArgumentParser(description="ZotakAI Security Assistant")
    parser.add_argument("--check-tools", action="store_true", help="Check and install security tools")
    parser.add_argument("--reset-config", action="store_true", help="Reset configuration to defaults")
    parser.add_argument("--model", choices=["openrouter", "gemini", "dual"], help="Set the AI model or mode to use")
    parser.add_argument("--select", action="store_true", help="Force the AI provider selection menu to show")
    args = parser.parse_args()
    
    zotak_ai = ZotakAI()
    
    # Handle command line arguments
    if args.reset_config:
        zotak_ai.config = DEFAULT_CONFIG.copy()
        zotak_ai.save_config()
        console.print("[bold green]Configuration reset to defaults[/bold green]")
    
    if args.check_tools:
        zotak_ai.check_and_install_security_tools()
    
    if args.model:
        if args.model == "dual":
            zotak_ai.config["ai_provider_mode"] = "dual"
        else:
            zotak_ai.config["ai_provider_mode"] = "single"
            zotak_ai.config["default_model"] = args.model
        zotak_ai.save_config()
        console.print(f"[bold green]AI model set to {args.model}[/bold green]")
    
    # Force selection menu if requested
    if args.select:
        zotak_ai.config["first_run"] = True
        zotak_ai.save_config()
    
    # Run the main loop
    zotak_ai.run()

if __name__ == "__main__":
    main()
