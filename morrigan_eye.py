import scapy.all as scapy
import dns.resolver
import whois
from prettytable import PrettyTable
import logging
import argparse
import os
import socket
import colorama

# Initialize colorama for colored output
colorama.init()

# Setup logging
logging.basicConfig(filename='morrigan_eye.log', level=logging.INFO)

def setup_logging():
    logging.info("Morrigan Eye tool initiated.")

def packet_sniffer(interface):
    setup_logging()
    print(colorama.Fore.YELLOW + "Starting packet sniffer on interface: " + interface)
    scapy.sniff(iface=interface, prn=process_packet, store=0)

def process_packet(packet):
    logging.info(f"Packet captured: {packet.summary()}")
    print(packet.summary())

def dns_info(domain):
    setup_logging()
    print(colorama.Fore.CYAN + f"\nFetching DNS records for: {domain}")
    
    try:
        answers = dns.resolver.resolve(domain, 'A')
        print(colorama.Fore.GREEN + "A Records:")
        for rdata in answers:
            print(rdata.address)
            logging.info(f"A Record: {rdata.address}")
    except Exception as e:
        print(colorama.Fore.RED + f"Error fetching DNS records: {e}")

def whois_info(domain):
    setup_logging()
    print(colorama.Fore.CYAN + f"\nFetching WHOIS information for: {domain}")
    
    try:
        domain_info = whois.whois(domain)
        print(domain_info)
        logging.info(f"WHOIS Info: {domain_info}")
    except Exception as e:
        print(colorama.Fore.RED + f"Error fetching WHOIS information: {e}")

def port_scanner(target):
    setup_logging()
    print(colorama.Fore.CYAN + f"\nScanning ports on target: {target}")
    
    open_ports = []
    for port in range(1, 1025):  # Scanning common ports
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    
    if open_ports:
        print(colorama.Fore.GREEN + "Open ports:")
        for port in open_ports:
            print(port)
            logging.info(f"Open port: {port}")
    else:
        print(colorama.Fore.RED + "No open ports found.")

def network_scanner(interface):
    setup_logging()
    print(colorama.Fore.CYAN + f"\nScanning network on interface: {interface}")
    ip_range = scapy.get_if_addr(interface) + '/24'
    
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print(colorama.Fore.GREEN + "Available devices in the network:")
    for element in answered_list:
        print(f"IP: {element[1].psrc}, MAC: {element[1].hwsrc}")
        logging.info(f"Device found - IP: {element[1].psrc}, MAC: {element[1].hwsrc}")

def main():
    parser = argparse.ArgumentParser(description='Morrigan Eye - Advanced Network Reconnaissance Tool')
    parser.add_argument('-i', '--interface', help='Network interface to sniff packets', required=True)
    parser.add_argument('-d', '--domain', help='Domain to gather information', required=False)
    parser.add_argument('-t', '--target', help='Target IP for port scanning', required=False)
    parser.add_argument('-n', '--network', help='Network interface for scanning', required=False)

    args = parser.parse_args()
    
    if args.domain:
        dns_info(args.domain)
        whois_info(args.domain)
    
    if args.target:
        port_scanner(args.target)
    
    if args.network:
        network_scanner(args.network)

    packet_sniffer(args.interface)

if __name__ == '__main__':
    main()
