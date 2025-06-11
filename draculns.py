#!/usr/bin/env python3

import json
import os
import argparse
import nmap
from scapy.all import ARP, Ether, srp
from ipaddress import ip_network
from mac_vendor_lookup import MacLookup, VendorNotFoundError
from rich.console import Console, Group
from rich.table import Table
from rich import box
from rich.text import Text
from rich.live import Live
import time
import netifaces
import signal
import sys
import re
import unicodedata

os.system('clear')


live = None  # variável global

console = Console()

def sanitize_vendor_name(name):
    if not name:
        return ""
    name = unicodedata.normalize('NFKD', name).encode('ascii', 'ignore').decode('ascii')
    name = name.lower()
    name = re.sub(
        r'\b(inc|co|ltd|corp|electronics|mobile|corporation|limited|company|international|systems|gmbh|s\.a\.|s\.p\.a\.|s\.a\.r\.l\.|technologies|technology|device|group|industries|solutions|communications|telecom|holdings|info|computers|network|design|networks|innovation|trading|division|manufacturing|services|electronics|eletronica|do|brasil|ltda|sarl|spa)\b',
        '', name)
    name = re.sub(r'[\s\.,\-_\(\)\[\]/\\:;]+', '', name)
    return name.strip()

def load_mobile_vendors(json_path="/usr/share/draculns/mac_vendors.json"):
    if not os.path.exists(json_path):
        console.print(f"[bold red]Arquivo {json_path} não encontrado![/bold red]")
        return set()
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return set(sanitize_vendor_name(v) for v in data)

MOBILE_DEVICE_MANUFACTURERS = load_mobile_vendors()

def logo():
    console.print(
        r"""
     [yellow] _____                            _  _   _   _____ [/yellow]
     [yellow]|  __ \                          | || \ | | / ____|[/yellow]
     [yellow]| |  | | _ __  __ _   ___  _   _ | ||  \| || (___  [/yellow]
     [yellow]| |  | || '__|/ _` | / __|| | | || || . ` | \___ \ [/yellow]
     [yellow]| |__| || |  | (_| || (__ | |_| || || |\  | ____) |[/yellow]
     [yellow]|_____/ |_|   \__,_| \___| \__,_||_||_| \_||_____/ [/yellow]
     [yellow]                       v2.0                        [/yellow]
        """
    )

def display_banner():
    console.print(
        "\n[bold red]=================================================================[/bold red]"
        "\n[bold red] [*] ATENÇÃO: Este script é apenas para fins educacionais.[/bold red]"
        "\n[bold red] [*] Não o use para atividades ilegais.[/bold red]"
        "\n[bold red] [*] Não me responsabilizo por qualquer uso indevido deste script.[/bold red]"
        "\n[bold red]=================================================================[/bold red]"
    )
    console.print(
        "\n[bold blue] [*] Autor: Fábio Monteiro[/bold blue]"
        "\n[bold cyan] [*] GitHub: https://github.com/fabiosilvamonteiro/[/bold cyan]"
        "\n[bold cyan] [*] LinkedIn: https://www.linkedin.com/in/fabio-silva-monteiro/[/bold cyan]\n"
    )

def interruptMsg():
    console.print("")

def validate_interface(interface):
    return interface in netifaces.interfaces()

def validate_network(network):
    try:
        ip_network(network)
        return True
    except ValueError:
        return False

def signal_handler(sig, frame):
    global live
    interruptMsg()
    if live is not None:
        live.stop()  # fecha a visualização do Live para não deixar lixo na tela
    sys.exit(0)
    
def async_scan_network(network):
    target_ip = str(network)
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    try:
        result = srp(packet, timeout=0.3, verbose=0)[0]
        devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]
        return devices
    except Exception as e:
        console.print(f"[bold red] [*] Ocorreu um erro ao varrer a rede: {str(e)}[/bold red]")
        return []

def scan_ports_for_device(device):
    nm = nmap.PortScanner()
    ip = device['ip']

    try:
        nm.scan(ip, arguments='--min-parallelism 5 -sV -n -Pn -T5')

        if ip in nm.all_hosts():
            host_data = nm[ip]
            if 'hostscript' in host_data:
                del host_data['hostscript']
            return host_data

        console.print(f"[bold yellow] [*] A varredura rápida falhou para {ip}, tentando varredura completa.[/bold yellow]")
        nm.scan(ip, arguments='--min-parallelism 5 -p- -sV -n -Pn -T5 --script=firewall-bypass')
        if ip in nm.all_hosts():
            host_data = nm[ip]
            if 'hostscript' in host_data:
                del host_data['hostscript']
            return host_data

        return {'error': f"Não foi possível varrer as portas para o IP {ip}. Nenhuma informação disponível."}

    except Exception as e:
        return {'error': f"Ocorreu um erro ao varrer as portas para o IP {ip}: {str(e)}"}

def get_port_color(state):
    colors = {'open': 'green'}
    return colors.get(state)

def get_important_port_color(port, state):
    if port in [22, 5555] and state == 'open':
        return 'yellow'
    return get_port_color(state)

def guess_mobile_from_mac(mac):
    try:
        first_byte = int(mac.split(":")[0], 16)
        return (first_byte & 2) == 2
    except:
        return False

def sanitize_and_check_mobile(vendor):
    sanitized = sanitize_vendor_name(vendor)
    return any(mob_vendor in sanitized for mob_vendor in MOBILE_DEVICE_MANUFACTURERS)

def print_device_info(device, port_scan=None):
    try:
        mac_lookup = MacLookup()
        vendor = mac_lookup.lookup(device['mac'])
    except VendorNotFoundError:
        vendor = "Desconhecido"

    sanitized_vendor = sanitize_vendor_name(vendor)
    likely_mobile = any(mob_vendor in sanitized_vendor for mob_vendor in MOBILE_DEVICE_MANUFACTURERS)
    mobile_reason = ""
    if not likely_mobile:
        if guess_mobile_from_mac(device['mac']):
            likely_mobile = True
            mobile_reason = "MAC local/random (provável dispositivo móvel)"
        elif vendor == "Desconhecido":
            mobile_reason = "Vendor MAC desconhecido, pode ser dispositivo móvel moderno"
        elif port_scan:
            found = False
            for proto in port_scan.all_protocols():
                for port in port_scan[proto]:
                    if int(port) in [5555, 62078, 5037, 5228]:
                        likely_mobile = True
                        found = True
                        mobile_reason = f"Porta típica de mobile aberta: {port}"
                        break
                if found:
                    break

    box_content = (
        f" [*] Dispositivo: [bold blue]{device['ip']}[/bold blue]\n"
        f" [*] MAC: [bold green]{device['mac']}[/bold green]\n"
        f" [*] Fabricante: {'[bold yellow]' + vendor + '[/bold yellow]'}\n"
        f" [*] Provavelmente um dispositivo móvel: {'[bold green]Sim[/bold green]' if likely_mobile else '[bold red]Não[/bold red]'}"
        #f" [*] Motivo: {mobile_reason}"
    )

    console.print("┌" + ("─" * 68) + "┐")
    console.print(box_content)
    console.print("└" + ("─" * 68) + "┘")

    return vendor

def print_open_ports(port_scan):
    table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
    table.add_column("Protocolo", style="cyan")
    table.add_column("Porta", style="cyan")
    table.add_column("Estado", style="cyan")
    table.add_column("Serviço", style="cyan")
    table.add_column("Produto", style="cyan")
    table.add_column("Versão", style="cyan")
    table.add_column("CPE", style="cyan")
    table.add_column("Extra Info", style="cyan")

    for proto in port_scan.all_protocols():
        for port in port_scan[proto].keys():
            state = port_scan[proto][port]['state']
            if state == 'open':
                service = port_scan[proto][port]['name']
                product = port_scan[proto][port]['product']
                version = port_scan[proto][port]['version']
                cpe = port_scan[proto][port]['cpe']
                extrainfo = port_scan[proto][port]['extrainfo']
                color = get_important_port_color(port, state)

                if color:
                    state = f"[{color}]{state}[/{color}]"
                    service = f"[{color}]{service}[/{color}]"
                    product = f"[{color}]{product}[/{color}]"
                    version = f"[{color}]{version}[/{color}]"
                    cpe = f"[{color}]{cpe}[/{color}]"
                    extrainfo = f"[{color}]{extrainfo}[/{color}]"

                table.add_row(proto, str(port), state, service, product, version, cpe, extrainfo)

    if not table.rows:
        console.print("\n[bold red] [*] Nenhuma porta aberta encontrada![/bold red]\n")
    else:
        console.print(table)

def scan_and_print_once(networks):
    devices = []
    for network in networks:
        devices += async_scan_network(network)

    # Ordena os dispositivos por IP numericamente
    devices = sorted(devices, key=lambda d: tuple(int(o) for o in d['ip'].split('.')))
    
    if devices:
        plural = "s" if len(devices) > 1 else ""
        console.print(f"[bold yellow] [*] Dispositivo{plural} Encontrado{plural}:[/bold yellow]\n")
        table = Table(show_header=False, box=box.SQUARE)
        for device in devices:
            table.add_row(f"[bold cyan]{device['ip']}[/bold cyan] (MAC: [bold green]{device['mac']}[/bold green])")
        console.print(table)
        console.print(f"\n[bold yellow] [*] Analisando Dispositivo{plural}:[/bold yellow]\n")
        for device in devices:
            vendor = print_device_info(device)
            port_scan = scan_ports_for_device(device)
            if port_scan:
                print_open_ports(port_scan)
    else:
        console.print(f"\n[bold red] [*] Nenhum dispositivo encontrado![/bold red]\n")
    return devices

def scan_periodically(args, networks):
    global live
    signal.signal(signal.SIGINT, signal_handler)
    live = Live(console=console, refresh_per_second=0.5)
    live.start()
    try:
        while True:
            devices = []
            for network in networks:
                devices += async_scan_network(network)

            # Ordenar lista de dispositivos por IP numericamente
            devices = sorted(devices, key=lambda d: tuple(int(o) for o in d['ip'].split('.')))
            
            plural = "s" if len(devices) > 1 else ""
            if devices:
                table_summary = Table(show_header=True, header_style="bold yellow", box=box.SIMPLE)
                table_summary.add_column("IP", style="cyan")
                table_summary.add_column("MAC", style="green")
                table_summary.add_column("Fabricante", style="yellow")
                table_summary.add_column("Dispositivo móvel", style="magenta")
                table_summary.add_column("Portas abertas", style="cyan")
                table_summary.add_column("Versão", style="cyan")
                table_summary.add_column("CPE", style="cyan")
                table_summary.add_column("Extra Info", style="cyan")

                for device in devices:
                    try:
                        mac_lookup = MacLookup()
                        vendor = mac_lookup.lookup(device['mac'])
                    except VendorNotFoundError:
                        vendor = "Desconhecido"

                    port_scan = scan_ports_for_device(device)
                    open_ports = []
                    version = []
                    cpe = []
                    extrainfo = []
                    mobile = False

                    if port_scan and not port_scan.get('error'):
                        for proto in port_scan.all_protocols():
                            for port in port_scan[proto].keys():
                                if port_scan[proto][port]['state'] == 'open':
                                    open_ports.append(str(port))
                                    ver = port_scan[proto][port]['version']
                                    c = port_scan[proto][port]['cpe']
                                    ei = port_scan[proto][port]['extrainfo']
                                    version.append(ver if ver else "-")
                                    cpe.append(c if c else "-")
                                    extrainfo.append(ei if ei else "-")
                    else:
                        if port_scan and 'error' in port_scan:
                            open_ports.append(f"Erro: {port_scan.get('error')}")

                    sanitized_vendor = sanitize_vendor_name(vendor)
                    if any(mob_vendor in sanitized_vendor for mob_vendor in MOBILE_DEVICE_MANUFACTURERS):
                        mobile = True
                    elif guess_mobile_from_mac(device['mac']):
                        mobile = True

                    versao_str = ", ".join(sorted(set(version))) if version else "-"
                    cpe_str = ", ".join(sorted(set(cpe))) if cpe else "-"
                    extrainfo_str = ", ".join(sorted(set(extrainfo))) if extrainfo else "-"

                    table_summary.add_row(
                        device['ip'],
                        device['mac'],
                        vendor,
                        "[bold green]Sim[/bold green]" if mobile else "[bold red]Não[/bold red]",
                        ", ".join(open_ports) if open_ports else "-",
                        versao_str,
                        cpe_str,
                        extrainfo_str
                    )

                live.update(
                    Group(
                        Text(" [*] Resumo detalhado (atualização):", style="bold yellow"),
                        table_summary
                    )
                )
            else:
                live.update("[bold red] [*] Nenhum dispositivo encontrado![/bold red]\n")

            time.sleep(10)

    except KeyboardInterrupt:
        # Captura Ctrl+C dentro do loop para encerrar live sem erro
        pass
    finally:
        live.stop()
        live = None

def example_usage():
    return "python3 draculns.py -i eth0 -ip 192.168.0.0/24 -l"

def main():
    parser = argparse.ArgumentParser(description='Varredura de Rede', epilog=f'Exemplo de uso:\n  {example_usage()}')
    parser.add_argument('-ip', '--ip', nargs='+', default=['192.168.0.0/24'], help='endereços de rede')
    parser.add_argument('-i', '--interface', default='eth0', help='interface de rede')
    parser.add_argument('-l', '--loop', action='store_true', help='executar varredura periodicamente')
    args = parser.parse_args()

    if not validate_interface(args.interface):
        console.print("[bold red] [*] Interface inválida! Finalizando...[/bold red]")
        return

    try:
        networks = [ip_network(ip) for ip in args.ip]
    except ValueError:
        console.print(f"[bold red] \n [*] Erro ao analisar endereços de rede. A rede não possui um intervalo válido![/bold red]")
        return

    logo()
    display_banner()

    if args.loop:
        # Primeiro scan e print tradicional
        scan_and_print_once(networks)
        # Depois loop de atualização do resumo
        scan_periodically(args, networks)
    else:
        scan_and_print_once(networks)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        interruptMsg()
        sys.exit(0)
