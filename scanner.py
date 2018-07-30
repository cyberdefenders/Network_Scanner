from scapy.all import *
from scapy_http.http import *
import struct
import argparse  # Importing argument parser for commandline
import re  # Importing regex


# List of websites to filter by
WEBSITES = [
    ".com", ".org", ".net", ".edu", ".co",
    ".ai", ".xyz", ".training", ".io", ".uk",
    ".jpg", ".png", ".gif"
]


# A useful function that searches for a certain word in a string and returns it
def findwholeword(arg):
    return re.compile(r'\b({0})\b'.format(arg), flags=re.IGNORECASE).search


# Checks a string to see if it's equivalent to a boolean.
def checkbool(arg):
    if arg == "True":
        return True
    else:
        return False


# Checks to see if the livecapture is on/off
def getenablelivecapture():
    # Looks for livecapture in arglist and cleans up any unwanted special characters using REGEX
    condition = re.sub(r'[^\w]', '', str(getargs()['livecapture']))
    # After the string has been cleanup, then we can check if it's true/false
    if checkbool(condition):
        return True
    else:
        return False


def getpacketcount():
    # Looks for packetcount in arglist and cleans up any unwanted special characters using REGEX
    packetcount = re.sub(r'[^\w]', '', str(getargs()['packetcount']))
    # After the string has been cleanup, then we return the value specified
    return int(packetcount)


def getfilename():
    # Looks for filename in the arglist and cleans up any unwanted special characters using REGEX
    filename = re.sub(r'[^\w. ]', '', str(getargs()['filename']))
    # After the string has been cleanup, then we return the string specified
    return filename


def gettarget():
    # Looks for target in the arglist and cleans up any unwanted special characters using REGEX
    condition = re.sub(r'[^\w]', '', str(getargs()['target']))
    # After the string has been cleanup, then we return the string specified
    return condition


def getverbose():
    condition = re.sub(r'[^\w]', '', str(getargs()['verbose']))
    # After the string has been cleanup, then we can check if it's true/false
    if checkbool(condition):
        return True
    else:
        return False


# This function is WIP and not implemented yet
def getparse():
    # Looks for parsemode in the arglist and cleans up any unwanted special characters using REGEX
    condition = re.sub(r'[^\w]', '', str(getargs()['parsemode']))
    # After the string has been cleanup, then we return the string specified
    return condition


# Get args is perhaps one of the most important functions in this entire code
def getargs():
    # create parser object
    parser = argparse.ArgumentParser(description="A network analysis tool developed by Team Hercules.")

    #  These create the commands in console, the variables and their defaults, and other information
    parser.add_argument("-lc", "--livecapture", type=str, nargs=1,
                        metavar="livecapture", default="False",
                        help="Gathers new data as soon as the program starts. \n "
                             "If set to false, it will read whatever file you put under --filename <target> \n"
                             "Default: False")
    parser.add_argument("-pc", "--packetcount", type=str, nargs=1,
                        metavar="packetcount", help="Sets the packet count before program stops. Default: 200",
                        default="200")

    parser.add_argument("-fn", "--filename", type=str, nargs=1,
                        metavar='filename', default="Sketchy Stuff.pcap",
                        help="Name of the file. Default: Data.pcap")

    parser.add_argument("-t", "--target", type=str, nargs=1,
                        metavar='target', default="ARP",
                        help="Filter by a certain target [TCP, UDP, DNS, ARP, all or *] Default: all")

    parser.add_argument("-p", "--parsemode", type=str, nargs=1,
                        metavar='parsemode', default="True",
                        help="Should the program parse the packets? Default: True")

    parser.add_argument("-v", "--verbose", type=str, nargs=1,
                        metavar='verbose', default="False",
                        help="Should the program give more detail? Default: False")

    args = vars(parser.parse_args())  # We gather the arguments above and turn them into variables
    return args  # Returns the args as a list so we can parse later


def getpackets():
    if getenablelivecapture():  # If we're capturing data live..
        packets = sniff(count=getpacketcount(), filter=gettarget())  # sniff packets at the specified packetcount
        wrpcap(getfilename(), packets)  # Then write the data into the specified filename and the packets
        return packets  # Return all the packets recieved just now
    else:
        packets = rdpcap(getfilename())  # Read the packets from a specified file
        return packets  # Return the packets read from the file


# Here is where the real action happens
def filterpackets(packets):
    # For every packet in the group of packets..
    for pkt in packets:
        try:
            # If verbose mode is on...
            if getverbose():
                # Show more information about the packet than usual
                packetinfo = str(pkt.show())
            else:
                # Show the summary of that packet
                packetinfo = str(pkt.summary())
                # Filtering stuff below
            if gettarget() == "TCP":
                if findwholeword("TCP")(packetinfo):
                    print(packetinfo)

            elif gettarget() == "UDP":
                if findwholeword("UDP")(packetinfo):
                    print(packetinfo)

            elif gettarget() == "DNS":
                if findwholeword("DNS")(packetinfo):
                    print(packetinfo)

            elif gettarget() == "DNS Qry":
                if findwholeword("DNS Qry")(packetinfo):
                    print(packetinfo)

            elif gettarget() == "DNS Ans":
                if findwholeword("DNS Ans")(packetinfo):
                    print(packetinfo)

            elif gettarget() == "ARP":
                if findwholeword("ARP")(packetinfo):
                    print(packetinfo)

            elif gettarget() == "*" or gettarget() == "all":
                print(packetinfo)
            else:
                print("[Warning] Could not get target, please enter a valid target")
        # Incase the packet is corrupted, just skip to the next packet
        except AttributeError:
            continue


# All definitions below besides the main are WIP functions.
# They will be ready in a later version
def parsepacket(packets):
    print()
    for counter, pkt in enumerate(packets):
        protocolcheck(pkt, counter)
        # print(pkt.show())


def protocolcheck(packet, counter):
    if packet.haslayer(TCP):
        if getprotocol(packet) == "TCP" and gettarget() == "TCP":
            print(
                " ############ Packet #{} ############# \n".format(counter + 1),
                "############## IP Info ############# \n",
                "IP version: {} \n".format(getipversion(packet)),
                "Internet Header Length: {} \n".format(getinternetheaderlength(packet)),
                "Type of service: {} \n".format(gettypeofservice(packet)),
                "Protocol: {} \n".format(getprotocol(packet)),
                "\n",
                "############## TCP Info ############# \n",
                "Source Port: {}\n".format(getsport(packet)),
                "Destination Port: {}\n".format(getdport(packet)),
                "Sequence: {}\n".format(getsequence(packet)),
                "Acknowledgement Number: {}\n".format(getacknowledgement(packet)),
                "Data offset: {}\n".format(getdataoffset(packet)),
                "Flags: {}\n".format(getflags(packet)),
                "Checksum: {}\n".format(getchksum(packet)),
            )
    elif packet.haslayer(ARP):
        if 'ARP' in packet and gettarget() == "ARP":
            print(
                " ############ Packet #{} ############# \n".format(counter + 1),
                "############## IP Info ############# \n",
                "IP version: {} \n".format(getipversion(packet)),
                "Internet Header Length: {} \n".format(getinternetheaderlength(packet)),
                "Type of service: {} \n".format(gettypeofservice(packet)),
                "Protocol: {} \n".format(getprotocol(packet)),
                "\n",
                "############## ARP Info ############# \n",
                "Hardware type: {}\n".format(gethwtype(packet)),
                "Protocol type: {}\n".format(getprototype(packet)),
                "Hardware Length: {}\n".format(gethwlength(packet)),
                "Protocol length: {}\n".format(getprotolength(packet)),
                "Operation: {}\n".format(getoperation(packet)),
                "Hardware source: {}\n".format(gethwsource(packet)),
                "Protocol source: {}\n".format(getprotosource(packet)),
                "Hardware destination: {}\n".format(gethwdest(packet)),
                "Protocol destination: {}\n".format(getprotodest(packet)),
            )
            print("########### ARP Connection ###########")
            print(arp_display(packet))
            print()
            ###[ ARP ]###
            # hwtype = 0x1
            # ptype = 0x800
            # hwlen = 6
            # plen = 4
            # op = who - has
            # hwsrc = d0:e1: 40:9f: b5:7a
            # psrc = 172.28.96.25
            # hwdst = 00:00: 00:00: 00:00
            # pdst = 172.28.96.132


def arp_display(packet):
    if packet[ARP].op == 1:
        return "Request: {} is asking about {}".format(packet[ARP].psrc, packet[ARP].pdst)
    elif packet[ARP].op == 2:
        return "Response: {} has address {}".format(packet[ARP].hwsrc, packet[ARP].psrc)


def gethwtype(packet):
    hardwaretype = packet[ARP].hwtype

    if hardwaretype == 1:
        return str(hardwaretype) + " [Ethernet]"

    else:
        return str(packet[ARP].hwtype)


def getprototype(packet):
    return str(packet[ARP].ptype) + " [IP]"


def gethwlength(packet):
    return str(packet[ARP].hwlen) + " bits"


def getprotolength(packet):
    return str(packet[ARP].plen) + " bits"


def getoperation(packet):
    operation = packet[ARP].op

    if operation == 1:
        return str(operation) + " [Request]"
    elif operation == 2:
        return str(operation) + " [Reply]"
    else:
        return str(operation)


def gethwsource(packet):
    return str(packet[ARP].hwsrc)


def getprotosource(packet):
    return str(packet[ARP].psrc)


def gethwdest(packet):
    return str(packet[ARP].hwdst)


def getprotodest(packet):
    return str(packet[ARP].pdst)


def getsport(packet):
    if packet.haslayer(TCP):
        return str(packet[0][TCP].sport)
    if packet.haslayer(ARP):
        return str(packet[0][ARP].sport)


def getdport(packet):
    if packet.haslayer(TCP):
        if packet[TCP].dport == 443:
            return "https (Port 443)"
        if packet[TCP].dport == 80:
            return "http (Port 80)"
        else:
            return str(packet[TCP].dport)


def getsequence(packet):
    if packet.haslayer(TCP):
        return str(packet[TCP].seq)


def getacknowledgement(packet):
    if packet.haslayer(TCP):
        return str(packet[TCP].ack)


def getdataoffset(packet):
    if packet.haslayer(TCP):
        return str(packet[TCP].ack) + " [" + str(packet[TCP].dataofs * 4) + " Bytes]"


def getflags(packet):
    if packet.haslayer(TCP):
        if str(packet[TCP].flags) == "PA":
            return "PA [PSH+ACK] [Pushing the acknowledgement]"
        elif str(packet[TCP].flags) == "A":
            return "A [Acknowledgement]"
        else:
            return "Let me know to add this new flag! " + str(packet[0][TCP].flags)


def getchksum(packet):
    if packet.haslayer(TCP):
        return str(packet[TCP].chksum)


# A feature that is currently being worked on. Not yet used in main code yet
def getipversion(packet):
    if packet.haslayer(IP):
        return "IPv4"
    else:
        return "IPv6"


# A feature that is currently being worked on. Not yet used in main code yet
def getinternetheaderlength(packet):
    if packet.haslayer(IP):
        bytesize = (packet[0][IP].ihl * 32) / 8
        return str(packet[0][IP].ihl) + " or " + str(bytesize) + " bytes"
    else:
        return "[Missing IP layer]"


# A feature that is currently being worked on. Not yet used in main code yet
def gettypeofservice(packet):
    if packet.haslayer(IP):
        tos = str(packet[0][IP].tos)
        if tos in ("0", "04", "08", "0C", "10"):
            return str(packet[0][IP].tos) + " (Routine)"
        elif tos in ("20", "28", "30", "38"):
            return str(packet[0][IP].tos) + " (Priority)"
        elif tos in ("40", "48", "50", "58"):
            return str(packet[0][IP].tos) + " (Immediate)"
        elif tos in ("60", "68", "70", "78"):
            return str(packet[0][IP].tos) + " (Flash)"
        elif tos in ("80", "88", "90", "98"):
            return str(packet[0][IP].tos) + " (FlashOverride)"
        elif tos in ("A0", "B0", "B8"):
            return str(packet[0][IP].tos) + " (Critical"
        elif tos == "C0":
            return str(packet[0][IP].tos) + " (InterNetworkControl)"
        elif tos == "E0":
            return str(packet[0][IP].tos) + " (NetworkControl)"
        else:
            return "[Could not find type of service]" + str(packet[0][IP].tos)


# A feature that is currently being worked on. Not yet used in main code yet
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
        return None


# Main function, pretty much prints out the variable settings.
def main():

    if bool(getenablelivecapture()):
        print("Capturing data from a live network")
    else:
        print("Reading data from: " + getfilename())

    print("Packet count limit: " + str(getpacketcount()))
    print("File name: " + getfilename())
    print("Filtering by: " + str(gettarget()))
    print()
    if getparse():
        parsepacket(getpackets())
    else:
        filterpackets(getpackets())


# Runs the main
if __name__ == "__main__":
    main()

