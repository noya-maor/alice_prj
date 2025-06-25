from scapy.all import * 
mac_1 = "08:00:27:70:10:E7"
mac_2 = "08:00:27:93:77:9B" 

iface_1 = "enp0s8"
iface_2 = "enp0s9"

dst_mac_1 = "08:00:00:00:13:37"
dst_mac_2 = "0A:00:27:00:00:30"
def handle_packet(pkt):

    if (pkt[Ether].dst == mac_1):
        pkt.show()
        pkt[Ether].dst = dst_nac_2
        pkt[Ether].src = mac_2
        sendp(pkt, iface_2)

    elif(pkt[Ether].dst == mac_2):
        pkt.show()
        pkt[Ether].dst = dst_mac_1
        pkt[Ether].src = mac_1
        sendp(pkt, iface_1)
        pkt.show()

def main():
    pkts = sniff(prn = handle_packet)

if __name__ == "__main__":
    main()

