from scapy.all import *
from scapy_http.http import *
import struct
import argparse  # Importing argument parser for commandline
import re  # Importing regex


# A useful function that searches for a certain word in a string and returns it
def findwholeword(arg):
    return re.compile(r'\b({0})\b'.format(arg), flags=re.IGNORECASE).search

def textcleanup(arg):
    # Looks for parsemode in the arglist and cleans up any unwanted special characters using REGEX
    textcleanup = re.sub(r'[^\w]', '', str(arg))
    # After the string has been cleanup, then we return the string specified
    return textcleanup


def boolcleanup(arg):
    # Looks for parsemode in the arglist and cleans up any unwanted special characters using REGEX
    boolcleanup = re.sub(r'[^\w]', '', str(arg))
    # After the string has been cleanup, then we return the string specified
    if boolcleanup == "True" or boolcleanup == "true":
        return True
    else:
        return False

def filenamecleanup(arg):
    # Looks for filename in the arglist and cleans up any unwanted special characters using REGEX
    cleanfilename = re.sub(r'[^\w. ]', '', str(arg))
    # After the string has been cleanup, then we return the string specified
    return "data/" + str(cleanfilename)

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
                        metavar='filename', default="Pom.pcap",
                        help="Name of the file. Default: Data.pcap")

    parser.add_argument("-p", "--parsemode", type=str, nargs=1,
                        metavar='parsemode', default="True",
                        help="Should the program parse the packets? Default: True")

    parser.add_argument("-v", "--verbose", type=str, nargs=1,
                        metavar='verbose', default="True",
                        help="Should the program give more detail? Default: False")

    parser.add_argument("-i", "--input", type=str, nargs=1,
                        metavar='input', default="True",
                        help="Should the program switch to input? Default: False")

    args = vars(parser.parse_args())  # We gather the arguments above and turn them into variables
    return args  # Returns the args as a list so we can parse later


def getpackets(livecapturearg, packetcountarg):
    if livecapturearg:  # If we're capturing data live..
        packets = sniff(count=packetcountarg, filter="ARP")  # sniff packets at the specified packetcount
        wrpcap(filename, packets)  # Then write the data into the specified filename and the packets
        return packets  # Return all the packets recieved just now
    else:
        packets = rdpcap(filename)  # Read the packets from a specified file
        return packets  # Return the packets read from the file



# Here is where the real action happens
def filterpackets(packets):
    # For every packet in the group of packets..
    for pkt in packets:
        try:
            print(str(pkt.show()))
        # Incase the packet is corrupted, just skip to the next packet
        except AttributeError:
            continue


def parsepacket(packets, verbosesetting):
    print()
    for counter, pkt in enumerate(packets):
        protocolcheck(pkt, counter, verbosesetting)


def protocolcheck(packet, counter, verbosesetting):
    if packet.haslayer(ARP):
        if bool(verbosesetting):
            print(
                " ############ Packet #{} ############# \n".format(counter + 1),
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
        else:
            print("########### ARP Connection [Packet #{}] ###########".format(counter + 1))
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
    # else:
        # print("No ARP packets found in " + filename)

def arp_display(packet):
    if packet[ARP].op == 1:
        return "[Request] {} is asking about {}".format(packet[ARP].psrc, packet[ARP].pdst)
    elif packet[ARP].op == 2:
        return "[Response] {} is at {}".format(packet[ARP].psrc, packet[ARP].hwsrc)


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
    if packet.haslayer(ARP):
        return str(packet[0][ARP].sport)
    else:
        return None


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
    with open('arps.csv', 'wb') as csvfile:
        writer = csv.writer(csvfile, delimiter=',', quoting=csv.QUOTE_NONNUMERIC)
        writer.writerow(['source', 'target', 'value'])
        #  output the dictionary
        for pair in dic:
            if dic[pair] > 1:
                    writer.writerow([pair[0], pair[1], dic[pair]])


livecapture = boolcleanup(getargs()['livecapture'])
packetcount = int(textcleanup(getargs()['packetcount']))
filename = filenamecleanup(getargs()['filename'])
parsemode = boolcleanup(getargs()['parsemode'])
verbose = boolcleanup(getargs()['verbose'])
input_var = boolcleanup(getargs()['input'])


def manualoverride(arg):
    if arg:
        return True
    else:
        return False


# Main function, pretty much prints out the variable settings.
def main():
    localpacketcount = packetcount
    localverbose = verbose
    localfilename = filename
    while True:
        print("Type the number for the option you want to choose")
        print("1. ARP File Analysis")
        print("2. ARP Live Analysis")
        print("3. ARP Attack")
        print("Type exit to quit the program")
        decision = input()
        if decision == "Exit" or decision == "exit":
            exit()

        elif textcleanup(decision) == "1":
            print("########## ARP File Analysis ##########")
            print()
            print("########## Settings ##########")
            while True:
                print("What is the filename of the pcap file? Default: " + str(localfilename) + " (Value: [Name].pcap)")
                filechoice = input()

                if filenamecleanup(filechoice) == '':
                    print("Using default filename: " + localfilename)
                    break
                else:
                    localfilename = filenamecleanup(filechoice)
                    print("Filename has been set to " + localfilename)
                    break

        elif textcleanup(decision) == "2":
            print("########## ARP Live Analysis ##########")
            print()
            print("########## Settings ##########")

            # PACKET COUNT
            print("How many packets should the program collect? Default: " + str(localpacketcount) + " (Value: [Number])")
            while True:
                numchoice = input()
                try:
                    if int(textcleanup(numchoice)) > 0:
                        print("Setting packet count to " + str(numchoice))
                        localpacketcount = numchoice
                        break
                except ValueError:
                    print("Using default setting [Packet count: " + str(localpacketcount) + "]")
                    break

            # PARSE MODE
            print()
            print("Enable simple packet analysis? Default: " + str(parsemode) + " (Value: [True/False])")
            temp = True
            while True:
                if temp:
                    choice = input()
                else:
                    choice = str(parsemode)
                if choice == "True" or choice == "true":
                    print("Simple packet analysis is enabled")
                    while True:
                        print()
                        print("Enable verbose mode for simple packet analysis? Default: " + str(verbose) + " (Value: [True/False])")
                        verbosechoice = input()
                        if textcleanup(verbosechoice) == "True" or verbosechoice == "true":
                            print("Verbose mode has been enabled")
                            localverbose = True
                            break
                        elif textcleanup(verbosechoice) == "False" or verbosechoice == "false":
                            print("Verbose mode has been disabled")
                            localverbose = False
                            break
                        else:
                            print("Using default setting [Verbose mode: " + str(localverbose) + "]")
                            break
                    print("Scanning... This might take some time")
                    parsepacket(getpackets(manualoverride(True), int(localpacketcount)), boolcleanup(localverbose))
                    print()
                    runagainchoice = input("Run again? Default: No (Value: [Yes/No])")
                    if runagainchoice == "Yes" or runagainchoice == "yes":
                        continue
                    else:
                        print()
                        break
                elif choice == "False" or choice == "false":
                    print("Simple packet analysis is disabled")
                    print()
                    print("Scanning... This might take some time")
                    filterpackets(getpackets(manualoverride(True), int(localpacketcount)))
                    print()
                    runagainchoice = input("Run again? Default: No (Value: [Yes/No])")
                    if runagainchoice == "Yes" or runagainchoice == "yes":
                        continue
                    else:
                        print()
                        break
                else:
                    print("Using default setting [Parse Mode: " + str(parsemode) + "]")
                    temp = False
                    continue
        else:
            print("Coming soon")
            break


# Runs the main
if __name__ == "__main__":
    main()

