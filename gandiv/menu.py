"""
GANDIV — Interactive Menu System
Menu-driven interface for multi-source OSINT reconnaissance.
"""

import sys
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich.table import Table

console = Console()


def show_banner():
    """Display GANDIV banner."""
    banner = """
[bold cyan]
   ██████╗  █████╗ ███╗   ██╗██████╗ ██╗██╗   ██╗
  ██╔════╝ ██╔══██╗████╗  ██║██╔══██╗██║██║   ██║
  ██║  ███╗███████║██╔██╗ ██║██║  ██║██║██║   ██║
  ██║   ██║██╔══██║██║╚██╗██║██║  ██║██║╚██╗ ██╔╝
  ╚██████╔╝██║  ██║██║ ╚████║██████╔╝██║ ╚████╔╝
   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═══╝
[/bold cyan]
[bold white]         GANDIV v2.0.0 — Never Miss Target Intelligence[/bold white]
[dim]         Multi-Source OSINT Reconnaissance Engine[/dim]
"""
    console.print(banner)


def main_menu() -> Optional[str]:
    """
    Display the main menu and return the user's choice.
    
    Returns:
        str: The chosen action key, or None if exit.
    """
    show_banner()
    
    console.print("\n[bold yellow]What do you want to do?[/bold yellow]\n")
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", width=6)
    table.add_column(style="white")
    
    table.add_row("[1]", "People OSINT          [dim]→ Email, phone, username, name[/dim]")
    table.add_row("[2]", "Domain Recon          [dim]→ Subdomains, DNS, WHOIS, certs[/dim]")
    table.add_row("[3]", "Web Recon             [dim]→ Tech stack, WAF, headers, JS secrets[/dim]")
    table.add_row("[4]", "Infrastructure Recon  [dim]→ IPs, ASN, Shodan, Censys, SSL[/dim]")
    table.add_row("[5]", "Breach & Leak Check   [dim]→ HIBP, DeHashed, paste sites[/dim]")
    table.add_row("[6]", "Username Enumeration  [dim]→ 300+ platforms[/dim]")
    table.add_row("[7]", "Reverse Image Search  [dim]→ Google, Yandex, TinEye[/dim]")
    table.add_row("[8]", "Full OSINT            [dim]→ All modules against any target[/dim]")
    table.add_row("[9]", "Custom Scan           [dim]→ Pick your own modules[/dim]")
    table.add_row("[0]", "Exit")
    
    console.print(table)
    
    choice = Prompt.ask(
        "\n[bold yellow]Enter choice[/bold yellow]",
        choices=["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"],
        default="0"
    )
    
    if choice == "0":
        console.print("\n[bold red]Exiting GANDIV. Stay ethical. 🛡️[/bold red]\n")
        return None
    
    return choice


def people_menu() -> Optional[str]:
    """
    Display the People OSINT sub-menu.
    
    Returns:
        str: The chosen input type, or None to go back.
    """
    console.print("\n[bold cyan]═══ People OSINT ═══[/bold cyan]\n")
    console.print("[bold yellow]What's your input type?[/bold yellow]\n")
    
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold cyan", width=6)
    table.add_column(style="white")
    
    table.add_row("[1]", "Email address")
    table.add_row("[2]", "Phone number")
    table.add_row("[3]", "Username")
    table.add_row("[4]", "Full name")
    table.add_row("[5]", "Back to main menu")
    
    console.print(table)
    
    choice = Prompt.ask(
        "\n[bold yellow]Enter choice[/bold yellow]",
        choices=["1", "2", "3", "4", "5"],
        default="5"
    )
    
    if choice == "5":
        return None
    
    return choice


def get_people_target(input_type: str) -> Optional[str]:
    """
    Prompt the user for the actual target value.
    
    Args:
        input_type: One of 'email', 'phone', 'username', 'name'.
    
    Returns:
        str: The target value, or None if cancelled.
    """
    prompts = {
        "email": "Enter email address",
        "phone": "Enter phone number (with country code)",
        "username": "Enter username",
        "name": "Enter full name",
    }
    
    prompt_text = prompts.get(input_type, "Enter target")
    target = Prompt.ask(f"\n[bold yellow]{prompt_text}[/bold yellow]")
    
    if not target.strip():
        console.print("[red]Empty input. Returning to menu.[/red]")
        return None
    
    return target.strip()


def run_interactive() -> Optional[dict]:
    """
    Run the full interactive menu flow.
    
    Returns:
        dict with 'action', 'type', 'target' — or None if exit.
    """
    while True:
        choice = main_menu()
        
        if choice is None:
            return None
        
        # People OSINT
        if choice == "1":
            sub_choice = people_menu()
            if sub_choice is None:
                continue
            
            type_map = {"1": "email", "2": "phone", "3": "username", "4": "name"}
            input_type = type_map.get(sub_choice)
            
            target = get_people_target(input_type)
            if target is None:
                continue
            
            return {
                "action": "people",
                "type": input_type,
                "target": target,
            }
        
        # Domain / Web / Infra / Breach / Username / Image / Full / Custom
        action_map = {
            "2": "domain",
            "3": "web",
            "4": "infra",
            "5": "breach",
            "6": "username",
            "7": "image",
            "8": "full",
            "9": "custom",
        }
        
        action = action_map.get(choice)
        
        if action in ("image",):
            console.print("\n[yellow]Image OSINT requires an image file path.[/yellow]")
            target = Prompt.ask("[bold yellow]Enter image path[/bold yellow]")
            if not target.strip():
                continue
            return {"action": action, "type": action, "target": target.strip()}
        
        target = Prompt.ask(f"\n[bold yellow]Enter target for {action} recon[/bold yellow]")
        if not target.strip():
            continue
        
        return {
            "action": action,
            "type": action,
            "target": target.strip(),
        }