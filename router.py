from scapy.all import *

mac_1 = "08:00:27:70:10:E7"
mac_2 = "08:00:27:93:77:9B"

iface_1 = "enp0s8"
iface_2 = "enpos9"

ip_1 = "192.168.56.101"
ip_2 = "192.168.167.2"

dst_mac_1 = "08:00:00:00:13:37"
dst_mac_2 = "0A:00:27:00:00:30"

dst_ip_1 = "192.168.56.1"

dst_ip_2 = "192.168.167.1"

id_port = 10000

nat_table = {} #{key = (src ip, src_port), value = id_port}
rev_table = {} #{key = id_port, value = (src ip, src_port)}

def handle_packet(pkt):
    if (pkt[Ether].dst == mac_1):
        pkt.show()

        pkt[Ether].dst = dst_mac_2
        pkt[Ether].src = mac_2

        
        if TCP in pkt:
            key = (pkt[IP].src, pkt[TCP].sport)
            id_port += 1
            if key not in nat_table:
                nat_table[key] = id_port
                rev_table[id_port] = key
            pkt[TCP].sport = nat_table[key]

        
        elif UDP in pkt:
            key = (pkt[IP].src, pkt[TCP].sport)
            id_port += 1
            if key not in nat_table:
                nat_table[key] = id_port
                rev_table[id_port] = key
            pkt[UDP].sport = nat_table[key]
        
        pkt[IP].src = ip_2
        pkt[IP].dst = dst_ip_2

        sendp(pkt, iface_2)

    elif(pkt[Ether].dst == mac_2):
        pkt.show()

        pkt[Ether].dst = dst_mac_1
        pkt[Ether].src = mac_1

        if TCP in pkt:
            if pkt[TCP].dport in rev_table:
                pkt[IP].dst, pkt[TCP].dport = rev_table[pkt[TCP].dport]
        
        elif UDP in pkt:
            if pkt[UDP].dport in rev_table:
                pkt[IP].dst, pkt[UDP].dport = rev_table[pkt[UDP].dport]        
        
        pkt[IP].src = ip_1
        pkt[IP].src = dst_ip_1

        sendp(pkt, iface_1)

    pkt.show()


def main():
    pkts = sniff(prn = handle_packet)


if __name__ == "__main__":
    main()

