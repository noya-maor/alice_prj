from scapy.all import UDP, TCP, Ether, IP, sendp, sniff

MAC_1 = "08:00:27:b4:4e:39"
MAC_2 = "08:00:27:62:9a:36"

IFACE_1 = "enp0s8"
IFACE_2 = "enpos9"

IP_1 = "192.168.56.102"
IP_2 = "192.168.167.3"

DST_MAC_2 = "08:00:00:00:13:37"
DST_MAC_1 = "0A:00:27:00:00:07"

DST_IP_1 = "192.168.56.1"
DST_IP_2 = "192.168.167.1"

ID_PORT = 10000
NAT_TABLE = {} #{key = (src ip, dst_ip, src_port), value = id_port}
REV_TABLE = {} #{key = id_port, value = (src ip, dst_ip src_port)}
def handle_packet(pkt):
    global ID_PORT
    if pkt[Ether].dst == MAC_1:
        pkt.show()

        pkt[Ether].dst = DST_MAC_2
        pkt[Ether].src = MAC_2

        
        if TCP in pkt:
            key = (pkt[IP].src, pkt[TCP].sport)
            ID_PORT += 1
            if key not in NAT_TABLE:
                NAT_TABLE[key] = ID_PORT
                REV_TABLE[ID_PORT] = key
            pkt[TCP].sport = NAT_TABLE[key]

        
        elif UDP in pkt:
            key = (pkt[IP].src, pkt[TCP].sport)
            ID_PORT += 1
            if key not in NAT_TABLE:
                NAT_TABLE[key] = ID_PORT
                REV_TABLE[ID_PORT] = key
            pkt[UDP].sport = NAT_TABLE[key]
        
        pkt[IP].src = IP_2
        sendp(pkt, IFACE_2)

    elif pkt[Ether].dst == MAC_2:
        pkt.show()

        pkt[Ether].dst = DST_MAC_1
        pkt[Ether].src = MAC_1

        if TCP in pkt:
            if pkt[TCP].dport in REV_TABLE:
                pkt[IP].dst, pkt[IP].src, pkt[TCP].dport = REV_TABLE[pkt[TCP].dport]
        
        elif UDP in pkt:
            if pkt[UDP].dport in REV_TABLE:
                pkt[IP].dst, pkt[IP].src, pkt[UDP].dport = REV_TABLE[pkt[UDP].dport]

        sendp(pkt, IFACE_1)

    pkt.show()


def main():
    pkts = sniff(prn = handle_packet)


if __name__ == "__main__":
    main()

