#!/usr/bin/env python3

import argparse
import nmap
from scapy.all import ARP, Ether, srp
from ipaddress import ip_network
from mac_vendor_lookup import MacLookup, VendorNotFoundError
from rich.console import Console
from rich.table import Table
from rich import box
import time
import schedule
import netifaces
from concurrent.futures import ThreadPoolExecutor

console = Console()
mac_lookup = MacLookup()


def display_banner():
    """
    Exibe um banner informativo no início da execução do script.
    """
    console.print(
"""
[bold red]=================================================================[/bold red]
[bold red] [*] ATENÇÃO: Este script é apenas para fins educacionais.[/bold red]
[bold red] [*] Não o use para atividades ilegais.[/bold red]
[bold red] [*] Não me responsabilizo por qualquer uso indevido deste script.[/bold red]
[bold red]=================================================================[/bold red]""")

    console.print(        
"""
[bold blue] [*] Autor: Fábio Monteiro[/bold blue]
[bold cyan] [*] GitHub: https://github.com/fabiosilvamonteiro/scripts_publicos[/bold cyan]
[bold cyan] [*] LinkedIn: https://www.linkedin.com/in/fabio-silva-monteiro/[/bold cyan]
""")

def validate_interface(interface):
    """
    Valida se a interface de rede especificada existe.
    """
    if interface not in netifaces.interfaces():
        console.print(f"[bold red] [*] A interface de rede '{interface}' não existe. Verifique o nome da interface e tente novamente.[/bold red]")
        return False

    return True


def validate_network(network):
    """
    Valida se o endereço de rede especificado é válido.
    """
    try:
        ip_network(network)
        return True
    except ValueError:
        console.print(f"[bold red] [*] '{network}' não é uma rede válida. Verifique o formato da rede e tente novamente.[/bold red]")
        return False


def scan_network(network, interface):
    """
    Executa a varredura da rede especificada usando ARP requests.
    Retorna uma lista de dispositivos encontrados com seus endereços IP e MAC.
    """
    target_ip = str(network)
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    try:
        result = srp(packet, timeout=1, verbose=0, iface=interface)[0]
        devices = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]
        return devices
    except Exception as e:
        console.print(f"[bold red] [*] Ocorreu um erro ao varrer a rede: {str(e)}[/bold red]")
        return []


def async_scan_ports(ip, nm):
    try:
        nm.scan(ip, arguments='--min-parallelism 10 --max-parallelism 50 --min-hostgroup 10 --max-hostgroup 50 -F -sV -n -Pn -T5')
        return nm[ip]
    except KeyError:
        console.print(f"[bold red] [*] A varredura rápida falhou para {ip}, tentando varredura completa.[/bold red]")
        try:
            nm.scan(ip, arguments='--min-parallelism 10 --max-parallelism 50 --min-hostgroup 10 --max-hostgroup 50 -p- -sV -n -Pn -T5 --script=firewall-bypass')
            return nm[ip]
        except Exception as e:
            console.print(f"[bold red] [*] Ocorreu um erro ao varrer as portas para o IP {ip}: {str(e)}[/bold red]")
            return nm[ip]
    except Exception as e:
        console.print(f"[bold red] [*] Ocorreu um erro desconhecido ao recuperar informações de porta: {str(e)}[/bold red]")
        return nm[ip]


def get_port_color(state):
    colors = {
        'open': 'green',
        'closed': 'red',
        'filtered': 'yellow'
    }
    return colors.get(state)


def is_likely_mobile(vendor):
    mobile_vendors = [
        'Apple', 'Samsung', 'Huawei', 'LG', 'Sony', 'HTC', 'Motorola', 'Nokia', 'ZTE', 'Xiaomi',
        'OnePlus', 'Realme', 'Google', 'Oppo', 'Vivo', 'Lenovo', 'Asus', 'BlackBerry', 'Meizu',
        'Honor', 'Smartisan', 'Tecno', 'Infinix', 'Alcatel', 'Panasonic', 'Sharp', 'TCL', 'Philips',
        'Lava', 'BLU', 'Itel', 'Gionee', 'Vodafone', 'Xolo', 'LeEco', 'Xiaolajiao', 'Evercoss', 'Advan',
        'Nubia', 'Umidigi', 'Elephone', 'Zopo', 'Doogee', 'Cubot', 'Symphony', 'Walton', 'Maxwest', 'Okapia',
        'Jolla', 'Blackview', 'ZTE', 'Itel', 'Greentel', 'Wing', 'Posh', 'Infone', 'Sendo', 'Trio', 'Verykool',
        'Plum', 'Vodafone', 'Celkon', 'BLU', 'OnePlus', 'Siemens', 'Motorola', 'SonyEricsson', 'BenQ', 'Palm',
        'Vertu', 'Emobile', 'Sewoo', 'Cellect', 'Semo', 'Heitech', 'Opera', 'Neken', 'Inno', 'INQ', 'TCG',
        'Xtouch', 'Neffos', 'Texet', 'Wexler', 'SKK', 'Energizer', 'ZUK', 'Highscreen', 'Texet', 'Lephone',
        'TP-Link', 'Greentel', 'Energizer', 'M-Horse', 'Polariod', 'Voto', 'Meitu', 'Vernee', 'ARK', 'Aquaris',
        'Pioneer', 'NEC', 'Dell', 'Philips', 'PCS Systemtechnik GmbH'
    ]
    return any(vendor.lower().startswith(mobile_vendor.lower()) for mobile_vendor in mobile_vendors)


def print_device_info(device):
    try:
        vendor = mac_lookup.lookup(device['mac'])
    except VendorNotFoundError:
        vendor = "Desconhecido"

    likely_mobile = is_likely_mobile(vendor)

    console.print(f" [*] Dispositivo: [bold blue]{device['ip']}[/bold blue]")
    console.print(f" [*] MAC: [bold green]{device['mac']}[/bold green]")
    console.print(f" [*] Fabricante: [bold yellow]{vendor}[/bold yellow]")
    console.print(f" [*] Provavelmente um dispositivo móvel: {'[bold green]Sim[/bold green]' if likely_mobile else '[bold red]Não[/bold red]'}")

    return vendor


def print_open_ports(port_scan):
    table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
    table.add_column("Protocolo", style="cyan")
    table.add_column("Porta", style="cyan")
    table.add_column("Estado", style="cyan")
    table.add_column("Serviço", style="cyan")
    table.add_column("Versão", style="cyan")

    for proto in port_scan.all_protocols():
        for port in port_scan[proto].keys():
            state = port_scan[proto][port]['state']
            service = port_scan[proto][port]['name']
            version = port_scan[proto][port]['version']
            color = get_port_color(state)

            if color:
                state = f"[{color}]{state}[/{color}]"

            if port in [22, 5555] and state == 'open':
                service = f"[{color}]{service}[/{color}]"

            table.add_row(proto, str(port), state, service, version)

    console.print("\n [*] Portas Abertas e Serviços:")
    console.print(table)


def async_scan_ports(ip, nm):
    try:
        nm.scan(ip, arguments='--min-parallelism 10 --max-parallelism 50 --min-hostgroup 10 --max-hostgroup 50 -F -sV -n -Pn -T5')
        return nm[ip]
    except KeyError:
        console.print(f"[bold red] [*] A varredura rápida falhou para {ip}, tentando varredura completa.[/bold red]")
        try:
            nm.scan(ip, arguments='--min-parallelism 10 --max-parallelism 50 --min-hostgroup 10 --max-hostgroup 50 -p- -sV -n -Pn -T5 --script=firewall-bypass')
            return nm[ip]
        except Exception as e:
            console.print(f"[bold red] [*] Ocorreu um erro ao varrer as portas para o IP {ip}: {str(e)}[/bold red]")
            return nm[ip]
    except Exception as e:
        console.print(f"[bold red] [*] Ocorreu um erro desconhecido ao recuperar informações de porta: {str(e)}[/bold red]")
        return nm[ip]

def scan_ports_for_device(device):
    nm = nmap.PortScanner()
    with ThreadPoolExecutor() as executor:
        port_scan = executor.submit(async_scan_ports, device['ip'], nm)
        if port_scan.result():
            print_open_ports(port_scan.result())



def scan_network_and_ports(network, interface):
    devices = scan_network(network, interface)
    for device in devices:
        vendor = print_device_info(device)
        scan_ports_for_device(device)


def scan_once(args, periodically=False):
    global mac_lookup
    networks = [ip_network(ip) for ip in args.ip]

    for network in networks:
        scan_network_and_ports(network, args.interface)

    if not periodically:
        console.print("[bold green] [*] Varredura concluída!")


def scan_periodically(args):
    def job():
        scan_once(args, True)

    schedule.every(1).minutes.do(job)

    while True:
        schedule.run_pending()
        time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description='Varredura de Rede')
    parser.add_argument('-ip', '--ip', nargs='+', default=['192.168.0.0/24'], help='endereços de rede')
    parser.add_argument('-i', '--interface', default='eth0', help='interface de rede')
    parser.add_argument('-l', '--loop', action='store_true', help='executar varredura periodicamente')

    args = parser.parse_args()

    if not validate_interface(args.interface):
        return

    for network in args.ip:
        if not validate_network(network):
            return

    if args.loop:
        scan_periodically(args)
    else:
        scan_once(args)


if __name__ == "__main__":
    display_banner()
    main()
