#! /usr/bin/env python
from scapy.all import *
import csv
import subprocess


class Displayer:
    def readpcap(self, pcap):
        pktlist = rdpcap(pcap)
        #  use dictionary to count the number of ARPs
        dic = {}
        for x in pktlist:
            #  check for ARP
            if ARP in x and x[ARP].op in (1, 2):
                    pkt = x[ARP]
                    pair = (pkt.psrc, pkt.pdst)
                    try:
                        dic[pair] += 1
                        #  try if this pair has occured in dictionary
                    except KeyError:
                        #  create new one
                        dic[pair] = 1
        #  write csv:
        with open('arps.csv', 'wb') as csvfile:
            writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_NONNUMERIC)
            writer.writerow(['source', 'target', 'value'])
            #  output the dictionary
            for pair in dic:
                if dic[pair] > 1:
                        writer.writerow([pair[0], pair[1], dic[pair]])


if __name__ == '__main__':
    dumpCall = ['/usr/bin/dumpcap', '-a', 'duration:120', '-i', 'wlan0', '-w', '/tracefiles/arps.pcap']
    dumpProc = subprocess.call(dumpCall, stdout=subprocess.PIPE, stderr=None)
    Display = Displayer()
    Display.readpcap('/tracefiles/arps.pcap')