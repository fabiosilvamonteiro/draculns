#!/usr/bin/env python3

# Importando bibliotecas necessárias
import argparse
import nmap
import time
import schedule
from scapy.all import ARP, Ether, srp
from ipaddress import ip_network
from mac_vendor_lookup import MacLookup, VendorNotFoundError
from rich.console import Console
from rich.table import Table
from rich import box

# Inicializando o console e o MacLookup
console = Console()
mac_lookup = MacLookup()

# Banner de aviso
console.print("\n[bold red]=================================================================[/bold red]")
console.print("[bold red] [*] ATENÇÃO: Este script é apenas para fins educacionais.[/bold red]")
console.print("[bold red] [*] Não use para fins criminosos.[/bold red]")
console.print("[bold red] [*] Não me responsabilizo por qualquer uso indevido deste script.[/bold red]")
console.print("[bold red]=================================================================[/bold red]")
console.print(f"\n[bold blue] [*] Autor: Fábio Monteiro[/bold blue]")
console.print(f"[bold cyan] [*] GitHub: https://github.com/fabiosilvamonteiro/scripts_publicos[/bold cyan]")
console.print(f"[bold cyan] [*] LinkedIn: https://www.linkedin.com/in/fabio-silva-monteiro/[/bold cyan]\n")


# Função para escanear a rede
def scan_network(network, interface):
    target_ip = str(network)  # Converte a rede para string
    arp = ARP(pdst=target_ip)  # Configura pacote ARP
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Configura pacote Ethernet
    packet = ether / arp  # Cria pacote

    # Envia pacote e recebe resposta
    result = srp(packet, timeout=3, verbose=0, iface=interface)[0]

    # Processa os dispositivos encontrados
    devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]

    return devices


# Função para escanear portas de um IP
def scan_ports(ip):
    nm = nmap.PortScanner()  # Inicializa o PortScanner
    try:
        nm.scan(ip, arguments='-F -sV')  # Modo rápido, detecção de serviço/versão
    except (nmap.PortScannerError, KeyError):
        console.print(f"[bold red] [*] A varredura rápida falhou para o {ip}, tentando varredura abrangente.[/bold red]")
        try:
            nm.scan(ip, arguments='-p 1-65535 -sV')  # Varredura completa
        except nmap.PortScannerError:
            console.print(f"[bold red] [*] A varredura abrangente também falhou para o {ip}.[/bold red]")
            return None

    return nm[ip]


# Função para verificar se o fornecedor é provavelmente de um dispositivo móvel
def is_likely_mobile(vendor):
    # Lista de fornecedores de dispositivos móveis
    mobile_vendors = ['apple', 'samsung', 'huawei', 'lg', 'sony', 'htc', 'motorola', 'nokia', 'zte', 'xiaomi', 'oneplus', 'realme', 'google', 'oppo', 'vivo', 'lenovo', 'asus', 'blackberry', 'meizu', 'honor', 'smartisan', 'tecno', 'infinix', 'alcatel', 'panasonic', 'sharp', 'tcl', 'philips', 'lava', 'blu', 'tecno', 'itel', 'gionee', 'vodafone', 'xolo', 'leeco', 'xiaolajiao', 'evercoss', 'advan', 'nubia', 'umidigi', 'elephone', 'zopo', 'doogee', 'cubot', 'symphony', 'walton', 'maxwest', 'okapia', 'jolla', 'blackview', 'zte', 'itel', 'greentel', 'wing', 'posh', 'infone', 'sendo', 'trio', 'verykool', 'plum', 'vodafone', 'celkon', 'blu', 'oneplus', 'siemens', 'motorola', 'sonyericsson', 'benq', 'palm', 'vertu', 'emobile', 'sewoo', 'cellect', 'semo', 'heitech', 'opera', 'neken', 'inno', 'inq', 'tcg', 'xtouch', 'neffos', 'texet', 'wexler', 'skk', 'energizer', 'zuk', 'highscreen', 'texet', 'lephone', 'tp-link', 'greentel', 'energizer', 'm-horse', 'polariod', 'voto', 'meitu', 'vernee', 'ark', 'aquaris', 'pioneer', 'nec', 'dell', 'philips']

    vendor_lower = vendor.lower()
    return any(vendor_lower.startswith(mobile_vendor) for mobile_vendor in mobile_vendors)


# Função para imprimir informações do dispositivo
def print_device_info(device):
    try:
        vendor = mac_lookup.lookup(device['mac'])
    except VendorNotFoundError:
        vendor = "Desconhecido"

    likely_mobile = is_likely_mobile(vendor)

    console.print(f"\nDispositivo: [bold blue]{device['ip']}[/bold blue]")
    console.print(f"MAC: [bold green]{device['mac']}[/bold green]")
    console.print(f"Fornecedor: [bold yellow]{vendor}[/bold yellow]")
    console.print(f"Provavelmente um dispositivo móvel: {'[bold green]Sim[/bold green]' if likely_mobile else '[bold red]Não[/bold red]'}")

    return vendor


# Função para imprimir as portas abertas
def print_open_ports(table, port_scan):
    for proto in port_scan.all_protocols():
        lport = port_scan[proto].keys()
        for port in lport:
            state = port_scan[proto][port]['state']
            service = port_scan[proto][port]['name']
            color = None

            if state == 'open':
                color = 'green'
            elif state == 'closed':
                color = 'red'
            elif state == 'filtered':
                color = 'yellow'

            if color:
                state = f"[{color}]{state}[/{color}]"

            if port in [22, 5555] and state == 'open':
                service = f"[{color}]{service}[/{color}]"

            table.add_row(proto, str(port), state, service)

    console.print("\nPortas Abertas e Serviços:")
    console.print(table)


# Função para escanear rede e portas
def scan_network_and_ports(network, interface):
    devices = scan_network(network, interface)
    for device in devices:
        vendor = print_device_info(device)

        try:
            port_scan = scan_ports(device['ip'])
            if port_scan:
                table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
                table.add_column("Protocolo", style="cyan")
                table.add_column("Porta", style="cyan")
                table.add_column("Estado", style="cyan")
                table.add_column("Serviço", style="cyan")

                print_open_ports(table, port_scan)
            else:
                console.print(f" [*] Não foi possível obter os resultados das portas para {device['ip']}")
        except (nmap.PortScannerError, KeyError) as e:
            console.print(f"[bold red] [*] Ocorreu um erro ao escanear as portas para o dispositivo.[/bold red]")

# Função para realizar uma única varredura
def scan_once(args, periodically=False):
    global mac_lookup
    networks = [ip_network(ip) for ip in args.ip]

    for network in networks:
        scan_network_and_ports(network, args.interface)

    if not periodically:
        console.print("[bold green] [*] Varredura completa!")


# Função para realizar varredura periodicamente
def scan_periodically(args):
    def job():
        scan_once(args, True)

    schedule.every(1).minutes.do(job)

    while True:
        schedule.run_pending()
        time.sleep(1)


# Função principal
def main():
    parser = argparse.ArgumentParser(description='Varredura de rede')
    parser.add_argument('-ip', '--ip', nargs='+', default=['192.168.0.0/24'], help='endereços de rede')
    parser.add_argument('-i', '--interface', default='eth0', help='interface de rede')
    parser.add_argument('-l', '--loop', action='store_true', help='realizar a varredura periodicamente a cada 1 minuto')

    args = parser.parse_args()

    if args.loop:
        scan_periodically(args)
    else:
        scan_once(args)


# Iniciando o script
if __name__ == "__main__":
    main()
