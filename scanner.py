from scapy.all import *  # Immports Scapy
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
#def getparse():
    # Looks for parsemode in the arglist and cleans up any unwanted special characters using REGEX
    # condition = re.sub(r'[^\w]', '', str(getargs()['parsemode']))
    # After the string has been cleanup, then we return the string specified
    # return condition


# Get args is perhaps one of the most important functions in this entire code
def getargs():
    # create parser object
    parser = argparse.ArgumentParser(description="A network analysis tool developed by Team Hercules.")

    #  These create the commands in console, the variables and their defaults, and other information
    parser.add_argument("-lc", "--livecapture", type=str, nargs=1,
                        metavar="livecapture", default="False",
                        help="Gathers new data as soon as the program starts. \n "
                             "If set to false, it will read whatever file you put under --filename <target> \n"
                             "Default: True")

    parser.add_argument("-pc", "--packetcount", type=str, nargs=1,
                        metavar="packetcount", help="Sets the packet count before program stops. Default: 200",
                        default="200")

    parser.add_argument("-fn", "--filename", type=str, nargs=1,
                        metavar='filename', default="OnePacket.pcap",
                        help="Name of the file. Default: Data.pcap")

    parser.add_argument("-t", "--target", type=str, nargs=1,
                        metavar='target', default="all",
                        help="Filter by a certain target [TCP, UDP, DNS, ARP, all or *] Default: all")

    parser.add_argument("-p", "--parsemode", type=str, nargs=1,
                        metavar='parsemode', default="True",
                        help="Should the program parse the packets? Default: False")

    parser.add_argument("-v", "--verbose", type=str, nargs=1,
                        metavar='verbose', default="True",
                        help="Should the program give more detail? Default: False")

    args = vars(parser.parse_args())  # We gather the arguments above and turn them into variables
    return args  # Returns the args as a list so we can parse later


# This is the function that is called for in order to get packets
def getpackets():
    if getenablelivecapture():  # If we're capturing data live..
        packets = sniff(getpacketcount())  # Then start sniffing the packets at the specified packetcount
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
    for counter, pkt in enumerate(packets):
        print(
            " ############ Packet #{} ############# \n".format(counter + 1),
            "############## IP Info ############# \n",
            "IP version: {} \n".format(getipversion(pkt)),
            "Internet Header Length: {} \n".format(getinternetheaderlength(pkt)),
            "Type of service: ({}) \n".format(gettypeofservice(pkt)),
            "Protocol: {} \n".format(getprotocol(pkt)),
        )
        protocolcheck(getprotocol(pkt))
        print()
        print(pkt.show())


def protocolcheck(packet):
    if packet.haslayer(IP):
        if getprotocol(packet) == "TCP":
            print(
                "############## TCP Info ############# \n",
                "Source Port: {}\n".format(getsport(packet)),
                "Destination Port: {}\n".format(getdport(packet)),
                "Sequence: {}\n".format(getsequence(packet)),
                "Acknowledgement Number: {}\n".format(getacknowledgement(packet)),
                "Data offset: {}\n".format(getdataoffset(packet)),
                "Flags: {}\n".format(getflags(packet)),
                "Checksum: {}\n".format(getchksum(packet)),
            )


def getsport(packet):
    if packet.haslayer(IP):
        if packet[0][IP].dport == "https":
            return "https (Port 443)"
        if packet[0][IP].dport == "http":
            return "http (Port 80)"
        else:
            return str(packet[0][IP].sport)


def getdport(packet):
    if packet.haslayer(IP):
        if packet[0][IP].dport == "https":
            return "https (Port 443)"
        if packet[0][IP].dport == "http":
            return "http (Port 80)"
        else:
            return str(packet[0][IP].dport)


def getsequence(packet):
    if packet.haslayer(IP):
        return str(packet[0][IP].seq)


def getacknowledgement(packet):
    if packet.haslayer(IP):
        return str(packet[0][IP].ack)


def getdataoffset(packet):
    if packet.haslayer(IP):
        return str(packet[0][IP].ack) + "[" + str(packet[0][IP].dataofs * 4) + " Bytes]"


def getflags(packet):
    if packet.haslayer(IP):
        if packet[0][IP].flags == "PA":
            return "PA [PSH+ACK] [Pushing the acknowledgement]"
        else:
            return "Let me know to add this new flag! " + str(packet[0][IP].flags)


def getchksum(packet):
    if packet.haslayer(IP):
        return str(packet[0][IP].chksum)



# A feature that is currently being worked on. Not yet used in main code yet
def getipversion(packet):
    if packet.haslayer(IP):
        if packet[0][IP].version == 4:
            return "IPv4"
        elif packet[0][IPv6].version == 6:
            return "IPv6"
    else:
        return "[Missing IP layer]"


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
        if tos in ("00", "04", "08", "0C", "10"):
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
        print("[Missing IP layer]")


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
    filterpackets(getpackets())
    # parsepacket(getpackets())


# Runs the main
if __name__ == "__main__":
    main()

