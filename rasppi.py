#! /usr/bin/env python
from scapy.all import *
import csv
import subprocess


def readpcap(pcapfilename):
    pktlist = rdpcap(pcapfilename)
    #  use dictionary to count the number of ARPs
    dic = {}
    for pack in pktlist:
        #  check for ARP
        if ARP in pack and pack[ARP].op in (1, 2):
                pkt = pack[ARP]
                pair = (pkt.psrc, pkt.pdst)
                try:
                    dic[pair] += 1
                    #  try if this pair has occured in dictionary
                except KeyError:
                    #  create new one
                    dic[pair] = 1
    #  write csv:
    with open('data/arps.csv', 'w') as csvfile:
        writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_NONNUMERIC)
        writer.writerow([b'source', b'target', b'value'])
        #  output the dictionary
        for pair in dic:
            if dic[pair] > 1:
                    writer.writerow([pair[0], pair[1], dic[pair]])


if __name__ == '__main__':
    dumpCall = ['-a', 'duration:120', '-i', 'wlan0', '-w', 'data/Pom.pcap']
    dumpProc = subprocess.call(dumpCall, stdout=subprocess.PIPE, stderr=None)
    Display = Displayer()
    Display.readpcap('data/Pom.pcap')