import socket
import os
import time
import threading
from scapy.all import ARP, Ether, srp
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.align import Align
from rich.prompt import Prompt
from mac_vendor_lookup import MacLookup

console = Console()
mac_lookup = MacLookup()

# Attempt to update the MAC vendor database silently
try:
    mac_lookup.update_vendors()
except Exception:
    pass

def get_vendor(mac):
    try:
        return mac_lookup.lookup(mac)
    except Exception:
        return "Unknown"

def get_local_subnet():
    """Attempts to guess the local /24 subnet based on the current IP."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        octets = local_ip.split('.')
        return f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    except Exception:
        return "192.168.1.0/24" # Fallback

def scan_network_worker(ip_range, results_container):
    """Background worker to perform the actual ARP scan."""
    arp_request = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_request

    try:
        # The srp function takes about 5 seconds to time out
        result = srp(packet, timeout=5, verbose=0)[0]
        devices = []
        for sent, received in result:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
                "vendor": get_vendor(received.hwsrc)
            })
        results_container['devices'] = devices
        results_container['status'] = 'success'
    except PermissionError:
        results_container['status'] = 'permission_error'
    except Exception as e:
        results_container['status'] = f'error: {e}'

def display_banner():
    # Clear the terminal for a fresh UI
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = """
[bold cyan]
 _   _      _                      _      _____                                 
| \ | |    | |                    | |    / ____|                                
|  \| | ___| |___      _____  _ __| | __| (___   ___ __ _ _ __  _ __   ___ _ __ 
| . ` |/ _ \ __\ \ /\ / / _ \| '__| |/ / \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |\  |  __/ |_ \ V  V / (_) | |  |   <  ____) | (_| (_| | | | | | | |  __/ |   
|_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\|_____/ \___\__,_|_| |_|_| |_|\___|_|   
[/bold cyan]
"""
    console.print(Align.center(banner))
    console.print(Align.center("[bold white]Advanced Network Reconnaissance Tool[/bold white]\n"))

def interactive_scan():
    while True:
        display_banner()
        
        ip_range = get_local_subnet()
        
        # Create an animated progress bar to simulate the scanning visuals
        with Progress(
            SpinnerColumn("bouncingBar", style="bold magenta"),
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(complete_style="green", finished_style="bold green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            console=console
        ) as progress:
            
            scan_task = progress.add_task(f"Scanning target subnet: {ip_range}...", total=100)
            
            # Run the actual scan in a separate thread so the UI can update smoothly
            results = {'status': 'running', 'devices': []}
            scan_thread = threading.Thread(target=scan_network_worker, args=(ip_range, results))
            scan_thread.start()
            
            # Animate the progress bar while waiting for the scan thread to finish
            while scan_thread.is_alive():
                time.sleep(0.1) # Update every 100ms
                # The ARP timeout is ~5s, so moving 2% per 0.1s gives a ~5s fill time
                if progress.tasks[scan_task].completed < 95:
                    progress.update(scan_task, advance=2)
            
            scan_thread.join()
            progress.update(scan_task, completed=100) # Snap to 100% when done
        
        # Handle scan results and errors
        if results['status'] == 'permission_error':
            console.print("\n[bold red]✖ Error: Administrator privileges required to send raw packets.[/bold red]")
            console.print("[red]Please restart your terminal/IDE as an Administrator and try again.[/red]\n")
            break
        elif results['status'].startswith('error'):
            console.print(f"\n[bold red]✖ Scanner encountered an error: {results['status']}[/bold red]\n")
            break
        
        devices = results.get('devices', [])
        
        # Render the final interactive UI table
        if not devices:
            console.print(Panel("[bold yellow]No devices found. Ensure you are connected to a network.[/bold yellow]", border_style="yellow"))
        else:
            table = Table(show_header=True, header_style="bold magenta", border_style="cyan", expand=True)
            table.add_column("🌐 IP Address", style="cyan", justify="center")
            table.add_column("🏷️ MAC Address", style="green", justify="center")
            table.add_column("🏢 Vendor", style="yellow", justify="center")

            for device in devices:
                table.add_row(device["ip"], device["mac"], device["vendor"])
            
            # Wrap the table in a stylized rich Panel
            panel = Panel(table, title="[bold green]Scan Results[/bold green]", subtitle=f"[cyan]Total Devices Found: {len(devices)}[/cyan]", border_style="green")
            console.print("\n")
            console.print(panel)
        
        # Interactive UI loop
        console.print("\n")
        choice = Prompt.ask("[bold cyan]Do you want to rescan the network?[/bold cyan]", choices=["y", "n"], default="n")
        if choice.lower() != 'y':
            console.print("\n[bold green]Exiting Network Scanner. Goodbye![/bold green]\n")
            break

if __name__ == "__main__":
    interactive_scan()