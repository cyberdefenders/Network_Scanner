from scapy.all import *
import argparse
import re


WEBSITES = [
    ".com", ".org", ".net", ".edu", ".co",
    ".ai", ".xyz", ".training", ".io", ".uk",
    ".jpg", ".png", ".gif"
]


def findwholeword(arg):
    return re.compile(r'\b({0})\b'.format(arg), flags=re.IGNORECASE).search


def checkbool(arg):
    if arg == "True":
        return True
    else:
        return False


def getenablelivecapture():
    condition = re.sub(r'[^\w]', '', str(getargs()['livecapture']))
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


def gettarget():
    condition = re.sub(r'[^\w]', '', str(getargs()['target']))
    return condition


def getparse():
    condition = re.sub(r'[^\w]', '', str(getargs()['parsemode']))
    return condition


def getverbose():
    condition = re.sub(r'[^\w]', '', str(getargs()['verbose']))
    if checkbool(condition):
        return True
    else:
        return False

def getargs():
    # create parser object
    parser = argparse.ArgumentParser(description="A network analysis tool developed by Team Hercules.")

    parser.add_argument("-lc", "--livecapture", type=str, nargs=1,
                        metavar="livecapture", default="False",
                        help="Gathers new data as soon as the program starts. Default: True")

    parser.add_argument("-pc", "--packetcount", type=str, nargs=1,
                        metavar="packetcount", help="Sets the packet count before program stops. Default: 2500",
                        default="200")

    parser.add_argument("-fn", "--filename", type=str, nargs=1,
                        metavar='filename', default="OnePacket.pcap",
                        help="Name of the file. Do not add .pcap to the end of the file! Default: data")

    parser.add_argument("-t", "--target", type=str, nargs=1,
                        metavar='target', default="all",
                        help="Filter by a certain target. Default: All")

    parser.add_argument("-p", "--parsemode", type=str, nargs=1,
                        metavar='parsemode', default="True",
                        help="Should the program parse the packets? Default: False")

    parser.add_argument("-v", "--verbose", type=str, nargs=1,
                        metavar='verbose', default="False",
                        help="Should the program give more detail? Default: False")

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


def parsepacket(packets):
    for counter, pkt in enumerate(packets):
        print(
            " ############ Packet #{} ############# \n".format(counter + 1),
            "############## IP Info ############# \n",
            "IP version: {} \n".format(getipversion(pkt)),
            "Internet Header Length: {} \n".format(getinternetheaderlength(pkt)),
            "Type of service: ({}) \n".format(gettypeofservice(pkt)),
            "Protocol: {} \n".format(getprotocol(pkt)),


              )
        print()
        print(pkt.show())


def getipversion(packet):
    if packet.haslayer(IP):
        if packet[0][IP].version == 4:
            return "IPv4"
        elif packet[0][IPv6].version == 6:
            return "IPv6"
    else:
        return "[Missing IP layer]"


def getinternetheaderlength(packet):
    if packet.haslayer(IP):
        bytesize = (packet[0][IP].ihl * 32) / 8
        return str(packet[0][IP].ihl) + " or " + str(bytesize) + " bytes"
    else:
        return "[Missing IP layer]"


def gettypeofservice(packet):
    if packet.haslayer(IP):
        tos = str(packet[0][IP].tos)
        if tos in ("0", "04", "08", "0C", "10"):
            return "Routine"
        elif tos in ("20", "28", "30", "38"):
            return "Priority"
        elif tos in ("40", "48", "50", "58"):
            return "Immediate"
        elif tos in ("60", "68", "70", "78"):
            return "Flash"
        elif tos in ("80", "88", "90", "98"):
            return "FlashOverride"
        elif tos in ("A0", "B0", "B8"):
            return "Critical"
        elif tos == "C0":
            return "InterNetworkControl"
        elif tos == "E0":
            return "NetworkControl"
        else:
            return "[Could not find type of service]"
    else:
        return "[Missing IP layer]"



def getprotocol(packet):
    if packet.haslayer(IP):
        if packet[0][IP].proto == 1:
            return "ICMP"
        elif packet[0][IP].proto == 2:
            return "IGMP"
        elif packet[0][IP].proto == 4:
            return "IPv4"
        elif packet[0][IP].proto == 6:
            return "TCP"
        elif packet[0][IP].proto == 1:
            return "ICMP"
        elif packet[0][IP].proto == 17:
            return "DNS"
        elif packet[0][IP].proto == 41:
            return "ICMP"
        else:
            print("Could not recognize a protocol. Here is the number: " + str(packet[0][IP].proto))
    else:
        print("[Missing IP layer]")


def filterpackets(packets):
    for pkt in packets:
        try:
            if getverbose():
                packetinfo = str(pkt.show())
            else:
                packetinfo = str(pkt.summary())

            if gettarget() == "TCP":
                if findwholeword("TCP")(packetinfo):
                    print(packetinfo)

            if gettarget() == "UDP":
                if findwholeword("UDP")(packetinfo):
                    print(packetinfo)

            if gettarget() == "DNS":
                if findwholeword("DNS")(packetinfo):
                    print(packetinfo)

            if gettarget() == "DNS Qry":
                if findwholeword("DNS Qry")(packetinfo):
                    print(packetinfo)

            if gettarget() == "DNS Ans":
                if findwholeword("DNS Ans")(packetinfo):
                    print(packetinfo)

            if gettarget() == "ARP":
                if findwholeword("ARP")(packetinfo):
                    print(packetinfo)

            if gettarget() == "*" or gettarget() == "all":
                print(packetinfo)

        except AttributeError:
            continue


def main():
    if bool(getenablelivecapture()):
        print("Capturing data from a live network")
    else:
        print("Reading data from: " + getfilename())

    print("Packet count limit: " + str(getpacketcount()))
    print("File name: " + getfilename())
    print("Filtering by: " + str(gettarget()))

    print()
    # filterpackets(getpackets())
    parsepacket(getpackets())


if __name__ == "__main__":
    main()

