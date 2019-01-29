# -*- coding: utf-8 -*-
import time
import sys
i, o, e, = sys.stdin, sys.stdout, sys.stderr
from scapy.all import *
sys.stdin, sys.stdout, sys.stderr = i, o, e


SPORT = 5000                # TCP source port
DPORT = 5001                # TCP destination port
ISN = 123                   # TCP initial sequence number
DST_IP = '127.0.0.1'        # Destination IP


def filter_synack(p):
    return TCP in p and p[TCP].flags==0x12


def main():
    """
    Add Documentation here
    """
    syn_packet = IP(dst=DST_IP)/TCP(sport=SPORT, dport=DPORT, seq=ISN, flags='S')
    print syn_packet.show()
    synack_packet = ""
    synack_packet = sr1(syn_packet, timeout=1)
    while synack_packet == None or synack_packet[TCP].flags != 0x12:
        synack_packet = sr1(syn_packet, timeout=1)
    ack_packet = IP(dst=DST_IP)/TCP(sport=SPORT, dport=DPORT, seq=synack_packet[TCP].ack, ack=synack_packet[TCP].seq+1, flags='A')
    send(ack_packet)


if __name__ == '__main__':
    main()