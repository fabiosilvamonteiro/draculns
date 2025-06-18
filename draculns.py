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
import concurrent.futures

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

def scan_and_print_once(networks):
    devices = []
    for network in networks:
        devices += async_scan_network(network)

    devices = sorted(devices, key=lambda d: tuple(int(o) for o in d['ip'].split('.')))

    plural = "s" if len(devices) > 1 else ""
    if devices:
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

def scan_ports_for_device(device):
    """
    Tenta escanear rapidamente portas comuns. Se não encontrar nada ou host não responder,
    tenta varredura completa. Sempre retorna dados formatados e fáceis de usar.
    """
    nm = nmap.PortScanner()
    ip = device['ip']
    FAST_ARGS = f'--min-parallelism 5 -sV -n -Pn -T5'
    FULL_ARGS = '--min-parallelism 5 -p- -sV -n -Pn -T4 --script=firewall-bypass --host-timeout 30s'

    try:
        nm.scan(ip, arguments=FAST_ARGS)
        if ip in nm.all_hosts():
            host_data = nm[ip]
            # Checa se achou alguma porta aberta
            portas_abertas = any(
                host_data.has_tcp(port) and host_data['tcp'][port]['state'] == 'open'
                for port in host_data['tcp']
            ) if 'tcp' in host_data else False

            if portas_abertas:
                if 'hostscript' in host_data:
                    del host_data['hostscript']
                return host_data
            #else:
                #console.print(f"\n[bold yellow] [*] Nenhuma porta comum aberta em {ip}, tentando varredura completa...[/bold yellow]")
        #else:
            #console.print(f"\n[bold yellow] [*] Host {ip} não respondeu ao scan rápido. Tentando varredura completa...[/bold yellow]")

        # Scan completo só se necessário
        nm.scan(ip, arguments=FULL_ARGS)
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
    """
    Recebe o objeto PortScanner (nmap.PortScanner) OU um dict com chave 'error'.
    - Se houver erro: exibe e retorna.
    - Caso contrário: mostra somente as portas abertas num quadro bonito.
    """
    # Caso a função anterior tenha retornado um dicionário de erro
    if isinstance(port_scan, dict):
        err = port_scan.get("error")
        if err:
            console.print(f"\n[bold red] [*] {err}[/bold red]\n")
        return

    table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
    table.add_column("Protocolo",  style="cyan")
    table.add_column("Porta",      style="cyan")
    table.add_column("Estado",     style="cyan")
    table.add_column("Serviço",    style="cyan")
    table.add_column("Produto",    style="cyan")
    table.add_column("Versão",     style="cyan")
    table.add_column("CPE",        style="cyan")
    table.add_column("Extra Info", style="cyan")

    for proto in port_scan.all_protocols():
        for port in port_scan[proto]:
            info = port_scan[proto][port]
            if info["state"] != "open":
                continue

            color = get_important_port_color(port, info["state"])
            row = [
                proto,
                str(port),
                info["state"],
                info["name"],
                info["product"],
                info["version"],
                info["cpe"],
                info["extrainfo"],
            ]

            # destaca portas 22 e 5555, se abertas
            if color:
                row = [f"[{color}]{cell}[/{color}]" if cell else "-" for cell in row]

            table.add_row(*row)

    if table.rows:
        console.print(table)
    else:
        console.print("\n[bold red] [*] Nenhuma porta aberta encontrada![/bold red]\n")

def scan_periodically(networks, refresh=10):
    """
    No primeiro ciclo faz scan de portas dos dispositivos.
    Nos seguintes, só verifica se ainda estão presentes.
    Se achar dispositivo novo, faz scan de portas só dele.
    """
    global live
    signal.signal(signal.SIGINT, signal_handler)
    prev_ips = set()
    device_info = {}   # ip: {'device': {...}, 'ports': {... ou None}}
    with Live(console=console, refresh_per_second=4) as live:
        while True:
            # Scan ARP
            current_devices = [d for net in networks for d in async_scan_network(net)]
            current_ips = set(d['ip'] for d in current_devices)
            new_ips = current_ips - prev_ips

            # Atualiza os dados dos dispositivos atuais (sem perder portas já escaneadas)
            for dev in current_devices:
                ip = dev['ip']
                if ip not in device_info:
                    device_info[ip] = {'device': dev, 'ports': None}

            # Faz scan de portas apenas para novos dispositivos
            if new_ips:
                # Faz em paralelo para acelerar caso muitos novos
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                    results = list(executor.map(scan_ports_for_device,
                                               [device_info[ip]['device'] for ip in new_ips]))
                for idx, ip in enumerate(new_ips):
                    device_info[ip]['ports'] = results[idx]

            # Monta painel de detalhes
            panels = []
            for ip in sorted(current_ips, key=lambda x: tuple(int(o) for o in x.split('.'))):
                dev = device_info[ip]['device']
                ports = device_info[ip]['ports']

                # Descoberta de fabricante e tipo de dispositivo
                try:
                    mac_lookup = MacLookup()
                    vendor = mac_lookup.lookup(dev['mac'])
                except VendorNotFoundError:
                    vendor = "Desconhecido"

                sanitized_vendor = sanitize_vendor_name(vendor)
                likely_mobile = any(mob_vendor in sanitized_vendor for mob_vendor in MOBILE_DEVICE_MANUFACTURERS)

                panel = Table.grid(padding=(0,1))
                panel.add_row(f"[bold blue]IP:[/bold blue] [cyan]{dev['ip']}[/cyan]")
                panel.add_row(f"[bold blue]MAC:[/bold blue] [green]{dev['mac']}[/green]")
                panel.add_row(f"[bold blue]Fabricante:[/bold blue] [yellow]{vendor}[/yellow]")
                panel.add_row(
                    "[bold blue]Dispositivo móvel:[/bold blue] " +
                    ("[bold green]Sim[/bold green]" if likely_mobile else "[bold red]Não[/bold red]")
                )
                panel.add_row("[bold blue]Portas abertas:[/bold blue]")

                table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
                table.add_column("Porta",      style="cyan")
                table.add_column("Protocolo",  style="cyan")
                table.add_column("Estado",     style="cyan")
                table.add_column("Serviço",    style="cyan")
                table.add_column("Produto",    style="cyan")
                table.add_column("Versão",     style="cyan")
                table.add_column("CPE",        style="cyan")
                table.add_column("Extra Info", style="cyan")

                any_open = False

                # Mostra erro, se presente
                if isinstance(ports, dict) and "error" in ports:
                    table.add_row("[red]-[/red]", "[red]-[/red]", "[red]-[/red]", "[red]-[/red]", "[red]-[/red]", "[red]-[/red]", "[red]-[/red]", f"[red]{ports['error']}[/red]")
                elif isinstance(ports, dict):
                    # TCP
                    for port, info in ports.get('tcp', {}).items():
                        if info["state"] != "open":
                            continue
                        color = get_important_port_color(port, info["state"])
                        row = [
                            str(port),
                            "tcp",
                            info.get("state", ""),
                            info.get("name", ""),
                            info.get("product", ""),
                            info.get("version", ""),
                            info.get("cpe", ""),
                            info.get("extrainfo", ""),
                        ]
                        if color:
                            row = [f"[{color}]{cell}[/{color}]" if cell else "-" for cell in row]
                        table.add_row(*row)
                        any_open = True
                    # UDP (opcional, se scan UDP for adicionado)
                    for port, info in ports.get('udp', {}).items():
                        if info["state"] != "open":
                            continue
                        color = get_important_port_color(port, info["state"])
                        row = [
                            str(port),
                            "udp",
                            info.get("state", ""),
                            info.get("name", ""),
                            info.get("product", ""),
                            info.get("version", ""),
                            info.get("cpe", ""),
                            info.get("extrainfo", ""),
                        ]
                        if color:
                            row = [f"[{color}]{cell}[/{color}]" if cell else "-" for cell in row]
                        table.add_row(*row)
                        any_open = True
                    if not any_open:
                        table.add_row("-", "-", "-", "-", "-", "-", "-", "[red]Nenhuma porta aberta[/red]")
                else:
                    table.add_row("-", "-", "-", "-", "-", "-", "-", "[yellow]Aguardando scan de portas...[/yellow]")

                panel.add_row(table)
                panels.append(panel)


            # Se algum IP saiu da rede, pode remover da visualização ou manter conforme desejar
            prev_ips = current_ips
            group = Group(*panels) if panels else Text("[bold red]Nenhum dispositivo encontrado![/bold red]")
            live.update(group)
            time.sleep(refresh)

def example_usage():
    return "sudo draculns -i eth0 -ip 192.168.0.0/24 -l"

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
        print("")
        print(" [*]-----------------------------Monitoramento Contínuo-----------------------------[*]\n")
        # Depois loop de atualização do resumo
        scan_periodically(networks, refresh=10)
    else:
        scan_and_print_once(networks)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        interruptMsg()
        sys.exit(0)
