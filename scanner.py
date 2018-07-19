# Initial file

from scapy.all import *

packets = rdpcap('Sketchy Stuff.pcap')

for packet in packets:
	if packet[0].getlayer(IP):
		ip_src = packet[0].getlayer(IP).src
		ip_dst = packet[0].getlayer(IP).dst
		if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
			ip_dns = packet[0].getlayer(DNS).qd.qname
			print("IP: " + str(ip_src) + " -> " + str(ip_dst) + " : (" + str(ip_dns))
		# print("IP: " + str(ip_src) + " -> " + str(ip_dst))
	#else:
		# print("No IP found")
