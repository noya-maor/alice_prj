from scapy.all import *
import argparse

mac_1 = "08:00:27:b4:4e:39"
mac_2 = "08:00:27:62:9a:36" 

iface_1 = "enp0s8"
iface_2 = "enp0s9"

ip_1 = "192.168.56.102"
ip_2 = "192.168.167.3"

dst_mac_2 = "08:00:00:00:13:37"
dst_mac_1 = "0A:00:27:00:00:07"

dst_ip_1 = "192.168.56.1"
dst_ip_2 = "192.168.167.1"


def handle_packet(pkt, client_1_ip, client_2_ip):
    if IP in pkt and (UDP in pkt or TCP in pkt):
        if(pkt[IP].src == client_1_ip):
            pkt[IP].src = ip_2
        elif(pkt[IP].src == client_2_ip):
            pkt[IP].src = ip_1

    if (pkt[Ether].dst == mac_1):
        pkt.show()
        pkt[Ether].dst = dst_mac_2
        pkt[Ether].src = mac_2
        sendp(pkt, iface_2)

    elif(pkt[Ether].dst == mac_2):
        pkt.show()
        pkt[Ether].dst = dst_mac_1
        pkt[Ether].src = mac_1
        sendp(pkt, iface_1)
    pkt.show()


def get_args():
    parser = argparse.ArgumentParser(description='Send data to server.')
    parser.add_argument('client_1_ip', type=str,
                        help='first client\'s ip')
    parser.add_argument('client_2_ip', type=str,
                        help='second client\'s ip')
    return parser.parse_args()


def main():
    args = get_args()
    sniff(prn=lambda pkt: handle_packet(pkt, args.client_1_ip, args.client_2_ip))


if __name__ == "__main__":
    main()
