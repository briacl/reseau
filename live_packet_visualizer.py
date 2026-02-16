#!/usr/bin/env python3
import socket
import struct
import textwrap
import os
import sys

# --- Configuration & Colors ---
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- Packet Parser ---
class PacketParser:
    def get_mac_addr(self, bytes_addr):
        bytes_str = map('{:02x}'.format, bytes_addr)
        return ':'.join(bytes_str).upper()

    def unpack_dns(self, data):
        # DNS Header: ID(2), Flags(2), Q(2), Ans(2), Auth(2), Add(2)
        trans_id, flags, questions, answers = struct.unpack('! H H H H', data[:8])
        qr = (flags >> 15) & 1 # 0=Query, 1=Response
        opcode = (flags >> 11) & 0xF
        rcode = flags & 0xF
        
        # Simple extraction of the first query domain name (if query)
        domain = ""
        try:
            if questions > 0:
                idx = 12
                while idx < len(data):
                    length = data[idx]
                    if length == 0: break
                    if length & 0xC0 == 0xC0: # Compression pointer
                        break # Too complex for simple script
                    idx += 1
                    domain += data[idx:idx+length].decode('utf-8', errors='ignore') + "."
                    idx += length
        except:
            domain = "<error parsing domain>"
            
        return trans_id, qr, opcode, rcode, domain, data[12:]

    def format_payload(self, data, width=60):
        # Determine if text or binary
        try:
            text = data.decode('utf-8')
            if all(32 <= ord(c) <= 126 or c in '\\r\\n\\t' for c in text):
                return textwrap.fill(text, width=width)
        except:
            pass
        
        # Binary/Mixed: Hexdump style
        output = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            text_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            output.append(f"{i:04X}  {hex_part:<48}  {text_part}")
        return '\\n'.join(output)

    def unpack_ethernet(self, data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
        return self.get_mac_addr(dest_mac), self.get_mac_addr(src_mac), proto, data[14:]

    def unpack_ipv4(self, data):
        version_header_len = data[0]
        version = version_header_len >> 4
        header_len = (version_header_len & 15) * 4
        ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
        return version, header_len, ttl, proto, self.ipv4(src), self.ipv4(target), data[header_len:]

    def ipv4(self, addr):
        return '.'.join(map(str, addr))

    def unpack_icmp(self, data):
        icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
        return icmp_type, code, checksum, data[4:]

    def unpack_tcp(self, data):
        (src_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])
        offset = (offset_reserved_flags >> 12) * 4
        flag_urg = (offset_reserved_flags & 32) >> 5
        flag_ack = (offset_reserved_flags & 16) >> 4
        flag_psh = (offset_reserved_flags & 8) >> 3
        flag_rst = (offset_reserved_flags & 4) >> 2
        flag_syn = (offset_reserved_flags & 2) >> 1
        flag_fin = offset_reserved_flags & 1
        return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

    def unpack_udp(self, data):
        src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
        return src_port, dest_port, size, data[8:]

    def unpack_arp(self, data):
        hw_type, proto_type, hw_len, proto_len, opcode, src_mac, src_ip, dst_mac, dst_ip = struct.unpack('! H H B B H 6s 4s 6s 4s', data[:28])
        return opcode, self.get_mac_addr(src_mac), self.ipv4(src_ip), self.get_mac_addr(dst_mac), self.ipv4(dst_ip)



# --- Visualizer ---
class Visualizer:
    def draw_ethernet(self, dest, src, proto):
        print(f"\n{Colors.BOLD}{Colors.HEADER}=== PAQUET CAPTURÉ ==={Colors.ENDC}")
        proto_name = "IPv4" if proto == 0x0800 else "ARP" if proto == 0x0806 else f"Unknown ({hex(proto)})"
        print(f"{Colors.BOLD}--- ETHERNET II ---{Colors.ENDC}")
        print(f"| {Colors.GREEN}DEST: {dest}{Colors.ENDC} | {Colors.BLUE}SRC: {src}{Colors.ENDC} | TYPE: {proto_name} |")
        print("+" + "-"*60 + "+")

    def draw_arp(self, opcode, src_mac, src_ip, dst_mac, dst_ip):
        op_str = "REQUEST (Qui est ?)" if opcode == 1 else "REPLY (C'est moi !)" if opcode == 2 else str(opcode)
        print(f"{Colors.BOLD}--- ARP ---{Colors.ENDC}")
        print(f"| Opcode: {op_str} |")
        print(f"| Sender: {Colors.BLUE}{src_mac}{Colors.ENDC} ({src_ip}) |")
        print(f"| Target: {Colors.GREEN}{dst_mac}{Colors.ENDC} ({dst_ip}) |")
        print("+" + "-"*60 + "+")

    def draw_ipv4(self, version, header_len, ttl, proto, src, target):
        proto_map = {1: "ICMP", 6: "TCP", 17: "UDP"}
        proto_str = proto_map.get(proto, str(proto))
        print(f"{Colors.BOLD}--- IPv4 ---{Colors.ENDC}")
        print(f"| Ver: {version} | HL: {header_len} | TTL: {ttl} | {Colors.WARNING}Proto: {proto_str}{Colors.ENDC} |")
        print(f"| {Colors.BLUE}SRC: {src}{Colors.ENDC}  -->  {Colors.GREEN}DST: {target}{Colors.ENDC} |")
        print("+" + "-"*60 + "+")

    def draw_icmp(self, type, code, checksum, data, parser_ref):
        type_map = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable"}
        type_str = type_map.get(type, str(type))
        print(f"{Colors.BOLD}--- ICMP ---{Colors.ENDC}")
        print(f"| Type: {type} ({Colors.BOLD}{type_str}{Colors.ENDC}) | Code: {code} | Checksum: {checksum} |")
        if len(data) > 0:
            print(f"| Payload:\n{parser_ref.format_payload(data)}")
        print("+" + "-"*60 + "+")

    def draw_dns(self, trans_id, qr, opcode, rcode, domain):
        msg_type = "RESPONSE" if qr else "QUERY"
        print(f"{Colors.BOLD}--- DNS ({msg_type}) ---{Colors.ENDC}")
        print(f"| ID: {trans_id} | Opcode: {opcode} | RCode: {rcode} |")
        if domain:
            print(f"| Domain: {Colors.CYAN}{domain}{Colors.ENDC} |")
        print("+" + "-"*60 + "+")

    def draw_tcp(self, src_port, dest_port, seq, ack, urg, ack_flag, psh, rst, syn, fin, data, parser_ref):
        flags = []
        if urg: flags.append("URG")
        if ack_flag: flags.append("ACK")
        if psh: flags.append("PSH")
        if rst: flags.append("RST")
        if syn: flags.append("SYN")
        if fin: flags.append("FIN")
        print(f"{Colors.BOLD}--- TCP ---{Colors.ENDC}")
        print(f"| {Colors.BLUE}PORT {src_port}{Colors.ENDC} --> {Colors.GREEN}PORT {dest_port}{Colors.ENDC} |")
        print(f"| SEQ: {seq} | ACK: {ack} | FLAGS: [{' '.join(flags)}] |")
        
        # HTTP Detection
        if len(data) > 0:
            str_data = data[:10].decode('utf-8', errors='ignore')
            if any(method in str_data for method in ['GET', 'POST', 'HTTP', 'PUT', 'DELETE']):
                print(f"{Colors.BOLD}--- HTTP ---{Colors.ENDC}")
            
            print(f"| Payload:\n{parser_ref.format_payload(data)}")
            
        print("+" + "-"*60 + "+")

    def draw_udp(self, src_port, dest_port, size, data, parser_ref):
        print(f"{Colors.BOLD}--- UDP ---{Colors.ENDC}")
        print(f"| {Colors.BLUE}PORT {src_port}{Colors.ENDC} --> {Colors.GREEN}PORT {dest_port}{Colors.ENDC} |")
        print(f"| Length: {size} |")
        print("+" + "-"*60 + "+")

# --- Main Parsing Loop ---
def main():
    if os.geteuid() != 0:
        print(f"{Colors.FAIL}ERREUR: Ce script doit être lancé en ROOT (sudo) pour capturer les paquets.{Colors.ENDC}")
        print("Usage: sudo python3 live_packet_visualizer.py [TARGET_IP]")
        sys.exit(1)

    target_ip = None
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]
        print(f"{Colors.GREEN}FILTRE ACTIVÉ : Affichage uniquement du trafic impliquant {target_ip}{Colors.ENDC}")

    parser = PacketParser()
    vis = Visualizer()
    
    # Création du socket RAW
    # ntohs(0x0003) capture tout le trafic Ethernet (ETH_P_ALL)
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    print(f"{Colors.GREEN}Capture en cours... Appuyez sur Ctrl+C pour arrêter.{Colors.ENDC}")
    print(f"{Colors.CYAN}ASTUCE : Si vous ne voyez pas le trafic externe, activez le 'Mirrored Mode' via wsl_ip_manager.py{Colors.ENDC}")
    
    try:
        while True:
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, payload_data = parser.unpack_ethernet(raw_data)
            
            should_show = False
            
            # Stockage temporaire pour affichage différé (si match)
            packet_layers = [] # Liste de tuples (fonction_draw, args)

            # 0x0800 = IPv4
            if eth_proto == 0x0800:
                version, header_len, ttl, proto, src, target, ip_payload = parser.unpack_ipv4(payload_data)
                
                # Filtrage IPv4
                if target_ip is None or target_ip == src or target_ip == target:
                    should_show = True
                    packet_layers.append((vis.draw_ethernet, (dest_mac, src_mac, eth_proto)))
                    packet_layers.append((vis.draw_ipv4, (version, header_len, ttl, proto, src, target)))

                    # ICMP
                    if proto == 1:
                        icmp_type, code, checksum, icmp_data = parser.unpack_icmp(ip_payload)
                        packet_layers.append((vis.draw_icmp, (icmp_type, code, checksum, icmp_data, parser)))
                    
                    # TCP
                    elif proto == 6:
                        src_port, dest_port, seq, ack, urg, ack_flag, psh, rst, syn, fin, tcp_data = parser.unpack_tcp(ip_payload)
                        packet_layers.append((vis.draw_tcp, (src_port, dest_port, seq, ack, urg, ack_flag, psh, rst, syn, fin, tcp_data, parser)))

                    # UDP
                    elif proto == 17:
                        src_port, dest_port, size, udp_data = parser.unpack_udp(ip_payload)
                        packet_layers.append((vis.draw_udp, (src_port, dest_port, size, udp_data, parser)))
                        
                        # DNS Detection (Port 53)
                        if src_port == 53 or dest_port == 53:
                            try:
                                trans_id, qr, opcode, rcode, domain, dns_payload = parser.unpack_dns(udp_data)
                                packet_layers.append((vis.draw_dns, (trans_id, qr, opcode, rcode, domain)))
                            except:
                                pass # Not DNS or parse error
            
            # 0x0806 = ARP
            elif eth_proto == 0x0806:
                opcode, src_mac_arp, src_ip, dst_mac_arp, dst_ip = parser.unpack_arp(payload_data)
                
                # Filtrage ARP
                if target_ip is None or target_ip == src_ip or target_ip == dst_ip:
                    should_show = True
                    packet_layers.append((vis.draw_ethernet, (dest_mac, src_mac, eth_proto)))
                    packet_layers.append((vis.draw_arp, (opcode, src_mac_arp, src_ip, dst_mac_arp, dst_ip)))

            # Affichage si le paquet passe le filtre
            if should_show and packet_layers:
                for draw_func, args in packet_layers:
                    draw_func(*args)

    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Arrêt de la capture.{Colors.ENDC}")
        sys.exit(0)

if __name__ == "__main__":
    main()
