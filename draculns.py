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
import signal
import sys
from concurrent.futures import ThreadPoolExecutor

console = Console()

MOBILE_DEVICE_MANUFACTURERS = set([
    'Apple', 'Samsung', 'Huawei', 'LG', 'Sony', 'HTC', 'Motorola', 'Nokia', 'ZTE', 'Xiaomi',
    'OnePlus', 'Realme', 'Google', 'Oppo', 'Vivo', 'Lenovo', 'Asus', 'BlackBerry', 'Meizu',
    'Honor', 'Smartisan', 'Tecno', 'Infinix', 'Alcatel', 'Panasonic', 'Sharp', 'TCL', 'Philips',
    'Lava', 'BLU', 'Itel', 'Gionee', 'Vodafone', 'Xolo', 'LeEco', 'Xiaolajiao', 'Evercoss', 'Advan',
    'Nubia', 'Umidigi', 'Elephone', 'Zopo', 'Doogee', 'Cubot', 'Symphony', 'Walton', 'Maxwest', 'Okapia',
    'Jolla', 'Blackview', 'Greentel', 'Wing', 'Posh', 'Infone', 'Sendo', 'Trio', 'Verykool',
    'Plum', 'Celkon', 'Siemens', 'SonyEricsson', 'BenQ', 'Palm',
    'Vertu', 'Emobile', 'Sewoo', 'Cellect', 'Semo', 'Heitech', 'Opera', 'Neken', 'Inno', 'INQ', 'TCG',
    'Xtouch', 'Neffos', 'Texet', 'Wexler', 'SKK', 'Energizer', 'ZUK', 'Highscreen', 'Texet', 'Lephone',
    'TP-Link', 'M-Horse', 'Polariod', 'Voto', 'Meitu', 'Vernee', 'ARK', 'Aquaris',
    'Pioneer', 'NEC', 'Dell', 'PCS Systemtechnik GmbH',
    'Acer', 'Amazon', 'Archos', 'BQ', 'Cat', 'Coolpad', 'Gigabyte', 'Haier', 'Hisense', 'Karbonn',
    'Kyocera', 'Lanix', 'Micromax', 'Microsoft', 'Prestigio', 'QMobile', 'Razer', 'RCA', 'RIM', 'Spice',
    'T-Mobile', 'Toshiba', 'ViewSonic', 'Wiko', 'YU', 'Barnes & Noble', 'BYD',
    'Coolpad', 'Casio', 'Cherry Mobile', 'Fujitsu', 'General Mobile', 'Geotel', 'Google', 'HP',
    'Hyundai', 'iBall', 'iBerry', 'Intex', 'K-Touch', 'Kogan', 'Lava', 'Lemon Mobiles',
    'Micromax', 'Microsoft', 'Mobiistar', 'MyPhone', 'NIU', 'Nubia', 'O+', 'Rivo Mobile', 'Salora',
    'Sonim', 'Tecno Mobile', 'Unnecto', 'Videocon', 'WickedLeak', 'Wiko Mobile', 'XOLO', 'Yota Devices',
    'Yu', 'Ziox', 'Zync', 'Black Shark', 'Nokia Mobile', 'Razer', 'vivo', 'IQOO', 'Barnes & Noble',
    'Bang & Olufsen', 'Bose', 'Bowers & Wilkins', 'BRAVEN', 'Jabra', 'Jaybird', 'JBL', 'Marshall', 'Sennheiser',
    'Skullcandy', 'Sonos', 'Beats by Dre', 'Ultimate Ears', 'V-Moda', 'Plantronics', 'SteelSeries', 'Audio-Technica',
    'RHA', 'Anker', '1MORE', 'JLab', 'AKG', 'Harman Kardon', 'FiiO', 'COWIN', 'Pioneer', 'AudioQuest', 'Hifiman',
    'Cambridge Audio', 'Shure', 'Sony', 'Beyerdynamic', 'Denon'
])

def logo():
    console.print(
        "\n     [yellow] _____                            _  _   _   _____ [/yellow]"
        "\n     [yellow]|  __ \                          | || \ | | / ____|[/yellow]"
        "\n     [yellow]| |  | | _ __  __ _   ___  _   _ | ||  \| || (___  [/yellow]"
        "\n     [yellow]| |  | || '__|/ _` | / __|| | | || || . ` | \___ \ [/yellow]"
        "\n     [yellow]| |__| || |  | (_| || (__ | |_| || || |\  | ____) |[/yellow]"
        "\n     [yellow]|_____/ |_|   \__,_| \___| \__,_||_||_| \_||_____/ [/yellow]"
        "\n     [yellow]                       v2.0                        [/yellow]"
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
    console.print("[bold red]\n [*] Execução Interrompida pelo usuário! Finalizando...[/bold red]")

def validate_interface(interface):
    """
    Valida se a interface de rede especificada existe.
    """
    return interface in netifaces.interfaces()

def validate_network(network):
    """
    Valida se o endereço de rede especificado é válido.
    """
    try:
        ip_network(network)
        return True
    except ValueError:
        return False

def signal_handler(signal, frame):
    """
    Função do manipulador para o sinal SIGINT.
    """
    interruptMsg()
    schedule.clear() # limpar todas as tarefas agendadas.
    sys.exit(0)

def async_scan_network(network):
    """
    Executa a varredura da rede especificada usando ARP requests.
    Retorna uma lista de dispositivos encontrados com seus endereços IP e MAC.
    """
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
    """
    Varre as portas do dispositivo usando Nmap.
    """
    nm = nmap.PortScanner()
    ip = device['ip']

    try:
        # Tenta a varredura rápida
        nm.scan(ip, arguments='--min-parallelism 5 -sV -n -Pn -T5')

        if ip in nm.all_hosts():
            host_data = nm[ip]
            if 'hostscript' in host_data:
                del host_data['hostscript']  # Remover scripts do resultado da varredura rápida para economizar espaço
            return host_data

        # Se a varredura rápida falhar, tenta a varredura completa
        console.print(f"[bold yellow] [*] A varredura rápida falhou para {ip}, tentando varredura completa.[/bold yellow]")
        nm.scan(ip, arguments='--min-parallelism 5 -p- -sV -n -Pn -T5 --script=firewall-bypass')
        if ip in nm.all_hosts():
            host_data = nm[ip]
            if 'hostscript' in host_data:
                del host_data['hostscript']  # Remover scripts do resultado da varredura completa para economizar espaço
            return host_data

        # Caso o IP não seja encontrado em ambas as varreduras, retornar uma mensagem de erro
        return {'error': f"Não foi possível varrer as portas para o IP {ip}. Nenhuma informação disponível."}

    except Exception as e:
        # Em caso de qualquer exceção, retornar uma mensagem de erro
        return {'error': f"Ocorreu um erro ao varrer as portas para o IP {ip}: {str(e)}"}

def get_port_color(state):
    """
    Retorna a cor associada ao estado da porta.
    """
    colors = {
        'open': 'green',
    }
    return colors.get(state)

def get_important_port_color(port, state):
    """
    Retorna a cor para portas importantes (como 22 e 5555) no estado 'open'.
    """
    if port in [22, 5555] and state == 'open':
        return 'yellow'
    return get_port_color(state)

def is_likely_mobile(vendor):
    """
    Verifica se é provável que o dispositivo seja móvel com base no fornecedor (vendor).
    """
    return any(vendor.lower().startswith(vendor_name.lower()) for vendor_name in MOBILE_DEVICE_MANUFACTURERS)

def print_device_info(device):
    try:
        mac_lookup = MacLookup()
        vendor = mac_lookup.lookup(device['mac'])
    except VendorNotFoundError:
        vendor = "Desconhecido"

    likely_mobile = is_likely_mobile(vendor)

    box_content = (
        f" [*] Dispositivo: [bold blue]{device['ip']}[/bold blue]\n"
        f" [*] MAC: [bold green]{device['mac']}[/bold green]\n"
        f" [*] Fabricante: {'[bold yellow]' + vendor + '[/bold yellow]'}\n"
        f" [*] Provavelmente um dispositivo móvel: {'[bold green]Sim[/bold green]' if likely_mobile else '[bold red]Não[/bold red]'}"
    )

    console.print("┌" + ("─" * 68) + "┐")
    console.print(box_content)
    console.print("└" + ("─" * 68) + "┘")

    return vendor


def print_open_ports(port_scan):
    """
    Exibe apenas as informações das portas abertas.
    """
    table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
    table.add_column("Protocolo", style="cyan")
    table.add_column("Porta", style="cyan")
    table.add_column("Estado", style="cyan")
    table.add_column("Serviço", style="cyan")
    table.add_column("Produto", style="cyan")
    table.add_column("Versão", style="cyan")
    table.add_column("CPE", style="cyan")  # Nova coluna para CPE
    table.add_column("Extra Info", style="cyan")  # Nova coluna para Extra Info

    for proto in port_scan.all_protocols():
        for port in port_scan[proto].keys():
            state = port_scan[proto][port]['state']
            if state == 'open':
                service = port_scan[proto][port]['name']
                product = port_scan[proto][port]['product']
                version = port_scan[proto][port]['version']
                cpe = port_scan[proto][port]['cpe']  # Adicionando a CPE
                extrainfo = port_scan[proto][port]['extrainfo']  # Adicionando a Extra Info
                color = get_important_port_color(port, state)

                if color:
                    state = f"[{color}]{state}[/{color}]"
                    service = f"[{color}]{service}[/{color}]"
                    product = f"[{color}]{product}[/{color}]"
                    version = f"[{color}]{version}[/{color}]"
                    cpe = f"[{color}]{cpe}[/{color}]"  # Colorir a CPE
                    extrainfo = f"[{color}]{extrainfo}[/{color}]"  # Colorir a Extra Info

                table.add_row(proto, str(port), state, service, product, version, cpe, extrainfo)  # Adicionando a CPE e Extra Info

    if not table.rows:
        console.print("\n[bold red] [*] Nenhuma porta aberta encontrada![/bold red]\n")
    else:
        console.print(table)


def scan_network_and_ports(networks, interface):
    """
    Varre a rede especificada e as portas dos dispositivos encontrados.
    """
    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(async_scan_network, network) for network in networks]
        for future in futures:
            devices = future.result()
            for device in devices:
                vendor = print_device_info(device)
                port_scan = scan_ports_for_device(device)
                if port_scan:
                    print_open_ports(port_scan)

def scan_periodically(args, networks):
    """
    Executa a varredura periodicamente.
    """
    def job():
        scan_network_and_ports(networks, args.interface)

    # Executa a varredura imediatamente antes de entrar no loop
    job()

    # Agenda a varredura para ser executada a cada 1 minuto
    schedule.every(1).minutes.do(job)

    while True:
        schedule.run_pending()
        time.sleep(1)

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
    except ValueError as e:
        console.print(f"[bold red] \n [*] Erro ao analisar endereços de rede. A rede não possui um intervalo válido![/bold red]")
        return

    logo()

    display_banner()

    if args.loop:
        signal.signal(signal.SIGINT, signal_handler)
        scan_periodically(args, networks)
    else:
        devices = []
        for network in networks:
            devices += async_scan_network(network)
        
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

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        interruptMsg()
        sys.exit(0)
