
from scapy.all import *

PACKETS = rdpcap('Sketchy Stuff.pcap')

enableWebsites = True
WEBSITES = [".com", ".org", ".net", ".edu", ".co", ".ai", ".xyz", ".training", ".io"]


def analysis(packets):
	for pkt in packets:
		try:
			ip_src = str(pkt.getlayer(IP).src)
			ip_dst = str(pkt.getlayer(IP).dst)
			#ip_addr = str(pkt.getlayer(IP).addr)
			if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:

				unsanitized_dns = str(pkt.getlayer(DNS).qd.qname)
				ip_dns = unsanitized_dns[2:-2]

				if enableWebsites:
					for counter, debug in enumerate(WEBSITES):
						if ip_dns[-4:] == WEBSITES[counter]:
							print(ip_dns + " IP: " + ip_src + " Connected to " + ip_dst)

				else:
					print(ip_dns + " (IP: " + ip_src + ") Connected to " + ip_dst)
		except AttributeError:
			continue


analysis(PACKETS)
