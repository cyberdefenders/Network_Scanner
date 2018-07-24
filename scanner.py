from scapy.all import *
import argparse
import re


WEBSITES = [
    ".com", ".org", ".net", ".edu", ".co",
    ".ai", ".xyz", ".training", ".io", ".uk",
    ".jpg", ".png", ".gif"
]

def checkbool(arg):
    if arg == "True":
        return True
    else:
        return False


def getenablelivecapture():
    condition = re.sub(r'[^\w]', '', str(getargs()['livecapture']))
    # print("Enable live capture is:" + str(condition))
    if checkbool(condition):
        return True
    else:
        return False


def getpacketcount():
    packetcount = re.sub(r'[^\w]', '', str(getargs()['packetcount']))
    return int(packetcount)


def getfilename():
    filename = re.sub(r'[^\w. ]', '', str(getargs()['filename']))
    return filename


def getwebsitefilter():
    condition = re.sub(r'[^\w]', '', str(getargs()['websitefilter']))
    # print("Website filter" + str(condition))
    if checkbool(condition):
        return True
    else:
        return False


def getargs():
    # create parser object
    parser = argparse.ArgumentParser(description="A network analysis tool developed by Team Hercules.")

    parser.add_argument("-lc", "--livecapture", type=str, nargs=1,
                        metavar="livecapture", default="True",
                        help="Gathers new data as soon as the program starts. Default: True")

    parser.add_argument("-pc", "--packetcount", type=str, nargs=1,
                        metavar="packetcount", help="Sets the packet count before program stops. Default: 2500",
                        default="500")

    parser.add_argument("-fn", "--filename", type=str, nargs=1,
                        metavar='filename', default="data",
                        help="Name of the file. Do not add .pcap to the end of the file! Default: data")

    parser.add_argument("-w", "--websitefilter", type=str, nargs=1,
                        metavar='websitefilter', default="True",
                        help="Enable or disable filtering by websites only. Default: True")

    parser.add_argument("-r", "--read", type=str, nargs=1,
                        metavar='read', default="data",
                        help="Read a pcap file. Notice: Packet count does not effect this. Default: data")

    # parse the arguments from standard input

    args = vars(parser.parse_args())
    return args


def getpackets():
    if getenablelivecapture():
        packets = sniff(getpacketcount())
        wrpcap(getfilename(), packets)
        return packets
    else:
        packets = rdpcap(getfilename())
        return packets


def analysis(packets):
    for pkt in packets:
        try:
            ip_src = str(pkt.getlayer(IP).src)
            ip_dst = str(pkt.getlayer(IP).dst)
            # ip_addr = str(pkt.getlayer(IP).addr)
            if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0:
                unsanitized_dns = str(pkt.getlayer(DNS).qd.qname)
                ip_dns = unsanitized_dns[2:-2]

                if getwebsitefilter():
                    for counter, debug in enumerate(WEBSITES):
                        if ip_dns[-4:] == WEBSITES[counter]:
                            print(ip_dns + " IP: " + ip_src + " Connected to " + ip_dst)
                else:
                    continue
            elif not getwebsitefilter():
                print("IP: " + ip_src + " Connected to " + ip_dst)

        except AttributeError:
            continue


def main():
    # print(getenablelivecapture())
    if bool(getenablelivecapture()):
        print("Livecapture: Enabled")
    else:
        print("Livecapture: Disabled -> " + getfilename())

    print("Packet count limit: " + str(getpacketcount()))
    print("File name: " + getfilename())

    if getwebsitefilter():
        print("Filter by websites only: Enabled")
    else:
        print("Filter by websites only: Disabled")

    print()
    analysis(getpackets())


if __name__ == "__main__":
    main()

