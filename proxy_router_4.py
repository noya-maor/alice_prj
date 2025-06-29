from scapy.all import UDP, TCP, IP, Ether, show, sniff, sendp
import argparse

MAC_1 = "08:00:27:b4:4e:39"
MAC_2 = "08:00:27:62:9a:36" 

IFACE_1 = "enp0s8"
IFACE_2 = "enp0s9"

IP_1 = "192.168.56.102"
IP_2 = "192.168.167.3"

DST_MAC_2 = "08:00:00:00:13:37"
DST_MAC_1 = "0A:00:27:00:00:07"

def handle_packet(pkt, client_1_ip, client_2_ip):
    if IP in pkt:
        if(pkt[IP].src == client_1_ip):
            pkt[IP].src = ip_2
        elif(pkt[IP].src == client_2_ip):
            pkt[IP].src = ip_1

        if(pkt[IP].dst == IP_2):
            pkt[IP].dst = client_1_ip
        elif(pkt[IP].dst == IP_1):
            pkt[IP].dst = client_2_ip

    if (pkt[Ether].dst == MAC_1):
        pkt.show()
        pkt[Ether].dst = DST_MAC_2
        pkt[Ether].src = MAC_2
        sendp(pkt, IFACE_2)

    elif(pkt[Ether].dst == MAC_2):
        pkt.show()
        pkt[Ether].dst = DST_MAC_1
        pkt[Ether].src = MAC_1
        sendp(pkt, IFACE_1)
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
