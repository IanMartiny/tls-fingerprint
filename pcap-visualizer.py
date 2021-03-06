#! /usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import math
import matplotlib.pyplot as plt
import mpld3
import numpy as np
from scapy_ssl_tls import *
from scapy.all import *

import sys

ACK = 0x10

def getArguments():
    if len(sys.argv) < 3:
        print("Need 2 arguments: pcap file and ip address")
        sys.exit(1)
    
    pcapFile = sys.argv[1]
    IPAddr = sys.argv[2]

    return pcapFile, IPAddr

def removeOtherPackets(packets, IPAddr):
    ret = []
    last = 0
    for i, packet in enumerate(packets):
        if not packet.haslayer(IP):
            continue

        IPLayer = packet.getlayer(IP)

        if IPLayer.dst == IPAddr or IPLayer.src == IPAddr:
            last = i
            if len(ret) == 0:
                print("first packet with IP: " + str(IPAddr) + " is #" + str(i))
            ret.append(packet)

    print("last packet with IP: " + str(IPAddr) + " is #" + str(last) + "\n")
    return ret

def findLayers(packet):
    layers = [packet.name]
    while packet.payload:
        packet = packet.payload
        layers.append(packet.name)
    
    return layers

def getTCPLen(packet):
    if (not packet.haslayer(TCP)) or (not packet.haslayer(IP)):
        print("Packet does not have either a TCP or IP layer, so can't find TCP len")
        return -1
    
    IPLayer = packet.getlayer(IP)
    TCPLayer = packet.getlayer(TCP)
    ip_total_len = IPLayer.len
    ip_header_len = IPLayer.ihl * 32 / 8
    tcp_header_len = TCPLayer.dataofs * 32 / 8
    tcpLen = ip_total_len - ip_header_len - tcp_header_len

    return tcpLen

def findRTT(packets, IPAddr):
    rtt = 100
    for ind, packet in enumerate(packets):
        if not packet.haslayer(TCP):
            continue
        # IPLayer = packet.getlayer(IP)
        if packet.getlayer(TCP).flags == ACK:
            continue
        if not (packet.getlayer(IP).dst == IPAddr)  :
            continue
        startTime = packet.time
        ackInd = findAck(packet, packets)
        endTime = packets[ackInd].time
        if (endTime - startTime) < rtt:
            rtt = endTime - startTime
            # print("updated RTT: rtt: {:<0.4}, ind: {:>3}, ackInd: {:>3}".format(rtt, ind, ackInd))

    return rtt


    # seqNum = 0
    # tcpLen = 0
    # startTime = 0
    # rtt = -1
    # for i, packet in enumerate(packets):
    #     if not (packet.haslayer(IP) and packet.haslayer(TCP)):
    #         print("error, packet (" + str(i) + ") doesn't have IP or TCP layer.")
    #         sys.exit(3)


    #     IPLayer = packet.getlayer(IP)
    #     if IPLayer.dst == IPAddr and seqNum == 0:
    #         TCPLayer = IPLayer.getlayer(TCP)
    #         seqNum = TCPLayer.seq
    #         tcpLen = getTCPLen(packet)
    #         startTime = packet.time

    #     elif seqNum != 0:
    #         TCPLayer = IPLayer.getlayer(TCP)
    #         ackNum = TCPLayer.ack
    #         if ackNum == seqNum + tcpLen:
    #             stopTime = packet.time
    #             rtt = stopTime - startTime
    #             break

    # return rtt 

def addDirectional(packet, topLayer, IPAddr, ret, stats):
    if packet.haslayer("IP"):
        IPLayer = packet.getlayer("IP")

        if IPLayer.dst == IPAddr:
            ret["packets"]["outgoing"]["count"] += 1
            ret[topLayer]["outgoing"]["count"] += 1
            size = IPLayer.len
            ret["packets"]["outgoing"]["size"] += size
            ret["packets"]["total"]["size"] += size
            ret[topLayer]["total"]["size"] += size
            ret[topLayer]["outgoing"]["size"] += size
            stats.append(size)
        else:
            ret["packets"]["incoming"]["count"] += 1
            ret[topLayer]["incoming"]["count"] += 1
            size = IPLayer.len
            ret["packets"]["incoming"]["size"] += size
            ret["packets"]["total"]["size"] += size
            ret[topLayer]["total"]["size"] += size
            ret[topLayer]["incoming"]["size"] += size
            stats.append(-size)
    
    return ret, stats

def counts(packets, IPAddr):
    ret = {"packets": {}}
    ret["packets"]["total"] = {"count": len(packets), "size": 0}
    ret["packets"]["outgoing"] = {"count": 0, "size": 0}
    ret["packets"]["incoming"] = {"count": 0, "size": 0}
    simpleStats = []
    zeroTime = packets[0].time

    for packet in packets:
        stats = [packet.time - zeroTime]
        layers = findLayers(packet)
        topLayer = layers[-1]
        stats.append(topLayer)
        if topLayer in ret:
            ret[topLayer]["total"]["count"] += 1
            ret, stats = addDirectional(packet, topLayer, IPAddr, ret, stats)
        else:
            ret[topLayer] = {}
            ret[topLayer]["total"] = {"count": 1, "size": 0}
            ret[topLayer]["incoming"] = {"count": 0, "size": 0}
            ret[topLayer]["outgoing"] = {"count": 0, "size": 0}
            ret, stats = addDirectional(packet, topLayer, IPAddr, ret, stats)
        
        simpleStats.append(stats)

    return ret, simpleStats


def printStats(cs, rtt):
    for label in cs:
        print("Number of %s in conversation: %d (%0.2f KB)" % (label, cs[label]["total"]["count"], cs[label]["total"]["size"]/1000.0))
        print("\tOutgoing: %3d (%0.2f KB)" % (cs[label]["outgoing"]["count"], cs[label]["outgoing"]["size"]/1000.0))
        print("\tIncoming: %3d (%0.2f KB)" % (cs[label]["incoming"]["count"], cs[label]["incoming"]["size"]/1000.0))

    print("RTT: " + str(rtt))

def getPacketSizes(packets):
    sizes = []
    for packet in packets:
        if not packet.haslayer(IP):
            continue
        sizes.append(packet.getlayer(IP).len)
    
    return sizes

def getTimestamp(packet):
    timeStamps = []
    options = packet.getlayer(TCP).options
    for option in options:
        if option[0] == "Timestamp":
            timeStamps = option[1]
            break
    
    return timeStamps

def getTCPTimes(packets, IPAddr):
    packet = packets[0]
    inTime = -1
    outTime = -1
    if (not packet.haslayer(IP)) or (not packet.haslayer(TCP)):
        print("can't get TCP time without IP/TCP layers")
        return inTime, outTime
    
    timeStamps = getTimestamp(packet)
    firstTime = timeStamps[0]
    ackInd = findAck(packet, packets)
    packet = packets[ackInd]
    timeStamps = getTimestamp(packet)
    secondTime = timeStamps[0]
    RTT = findRTT(packets, IPAddr)*100
    if packet.getlayer(IP).dst == IPAddr:
        inTime = firstTime - int(5*RTT)
        outTime = secondTime

    else:
        outTime = firstTime
        inTime = secondTime - int(5*RTT)

    # print("inTime : {:>10d}".format(inTime))
    # print("outTime: {:>10d}".format(outTime))
    
    return inTime, outTime
    
def add_arrow(line, position=None, direction='right', size=15, color=None):
    """
    add an arrow to a line.

    line:       Line2D object
    position:   x-position of the arrow. If None, mean of xdata is taken
    direction:  'left' or 'right'
    size:       size of the arrow in fontsize points
    color:      if None, line color is taken.
    """
    if color is None:
        color = line.get_color()

    xdata = line.get_xdata()
    ydata = line.get_ydata()

    if position is None:
        position = xdata[-2]
    # find closest index
    start_ind = np.argmin(np.absolute(xdata - position))
    if direction == 'right':
        end_ind = start_ind + 1
    else:
        end_ind = start_ind - 1

    line.axes.annotate('',
        xytext=(xdata[start_ind], ydata[start_ind]),
        xy=(xdata[end_ind], ydata[end_ind]),
        arrowprops=dict(arrowstyle="->", color=color),
        size=size
    )

def plotStats(packets, fileName, IPAddr):
    packetSep = 0.03
    currY = packetSep

    # sizes = getPacketSizes(packets)
    # print(sorted(sizes))
    zeroTime = packets[0].time
    # TCPIncomingZeroTime, TCPOutgoingZeroTime = getTCPTimes(packets, IPAddr)
    # print("TCPIncomingZeroTime: {:f}".format(TCPIncomingZeroTime))
    # print("ZeroTime: {:f}".format(zeroTime))
    # RTT = findRTT(packets, IPAddr)
    # TODO: plot incoming arrows based on TCP time (convert TCP time to relative time?, TCP time is accurate to ms)
    lastArrivalTime = 0
    lastRTT = 0
    for ind, packet in enumerate(packets):
        x = []
        y = []
        label = ""
        layersList = findLayers(packet)
        if (not packet.haslayer(IP)) or (not packet.haslayer(TCP)):
            continue
        if packet.getlayer(TCP).flags == ACK and getTCPLen(packet) == 0:
            continue
        if packet.getlayer(IP).src == IPAddr:
            endTime = lastArrivalTime - (0.5*lastRTT)
            startTime = packet.time - zeroTime
            lineLength = endTime-startTime
            x = np.linspace(startTime, endTime)
            if layersList[-1] == "SSL/TLS":
                color = "r"
                packetType = packet.getlayer(SSL).fields['records'][0].payload.name
                if packetType == "Raw":
                    size = len(packet.getlayer(SSL).fields['records'][0].payload.load)
                elif packetType == "TLS Ciphertext":
                    size = len(packet.getlayer(SSL).fields['records'][0].payload.data)
                elif packetType == "TLS Handshakes":
                    size = packet.getlayer(SSL).fields['records'][0].length

            elif layersList[-1] == "TCP":
                color = 'k'
                size = getTCPLen(packet)
            lw = size/100 + 2
            label = "Direction: {}, start: {:0.3f}, end: {:0.3f}, packet: {}, size: {}".format("incoming", startTime, endTime, ind, size)
        else:
            startTime = packet.time - zeroTime
            ackInd = findAck(packet, packets)
            endTime = packets[ackInd].time - zeroTime
            lastArrivalTime = endTime
            lastRTT = endTime-startTime
            x = np.linspace(startTime, endTime)
            lineLength = endTime-startTime
            if layersList[-1] == "SSL/TLS":
                color = "g"
                packetType = packet.getlayer(SSL).fields['records'][0].payload.name
                if packetType == "Raw":
                    size = len(packet.getlayer(SSL).fields['records'][0].payload.load)
                elif packetType == "TLS Ciphertext":
                    size = len(packet.getlayer(SSL).fields['records'][0].payload.data)
                elif packetType == "TLS Handshakes":
                    size = packet.getlayer(SSL).fields['records'][0].length
            elif layersList[-1] == "TCP":
                color = 'k'
                size = getTCPLen(packet)
            lw = size/100 + 2
            label = "Direction: {}, start: {:0.3f}, end: {:0.3f}, packet: {}, size: {}".format("outgoing", startTime, endTime, ind, size)

        currY += (lw/2)
        y = np.full(len(x), currY)
        line = plt.plot(x,y, color=color, lw=lw)[0]
        tooltip = mpld3.plugins.LineLabelTooltip(line, label=label)
        mpld3.plugins.connect(plt.gcf(), tooltip)
        add_arrow(line)
        currY += (packetSep)

    plt.ylim([0,currY])
    # plt.gca().invert_yaxis()
    # plt.show()
    plt.title(fileName)
    mpld3.show()
    # maxSize = max([x[2] for x in stats])
    # minSize = min([x[2] for x in stats])
    # largest = max([abs(maxSize), abs(minSize)])
    # largestScale = 0.8
    # XMAX = math.log(largest) / largestScale
    # for pair in stats:
    #     xmax = 0
    #     xmin = 0
    #     if pair[2] > 0:
    #         xmin = 0
    #         xmax = math.log(pair[2])
    #     else:
    #         xmax = XMAX
    #         xmin = XMAX - math.log(abs(pair[2]))
        
    #     if pair[1] == "TCP":
    #         color = 'k'
    #     elif pair[1] == "SSL/TLS":
    #         color = 'r'

    #     plt.hlines(pair[0],xmin, xmax, color)
    # plt.gca().invert_yaxis()
    # plt.xlim(0, XMAX)
    
    # plt.savefig(fileName+".png")
    # plt.show()




def statistics(packets, IPAddr, fileName):
    cs, stats = counts(packets, IPAddr)
    rtt = findRTT(packets, IPAddr)
    printStats(cs, rtt)

    plotStats(packets, fileName, IPAddr)

def findAck(packet, packets):
    if not packet.haslayer(TCP):
        print("Error: packet does not have TCP layer")
        return -1 
    TCPLayer = packet.getlayer(TCP)
    # print("TCPLayer.seq: " + str(TCPLayer.seq))
    # print("TCP len: " + str(getTCPLen(packet)))
    minAck = TCPLayer.seq + getTCPLen(packet)

    # print("minAck: " + str(minAck))
    packetInd = packets.index(packet)
    for i, v in enumerate(packets[packetInd:]):
        vTCPLayer = v.getlayer(TCP)
        if vTCPLayer.ack >= minAck:
            # print("i: " + str(i) + " v.ack: " + str(vTCPLayer.ack))
            # now check directions are right
            packetIPLayer = packet.getlayer(IP)
            tcpIPLayer = v.getlayer(IP)
            if packetIPLayer.src == tcpIPLayer.dst:
                return i + packetInd
    

    return -1



def main():
    pcapFile, IPAddr = getArguments()
    fileName = pcapFile.split(".")[0].split("/")[-1]

    try:
        packets = rdpcap(pcapFile)
    except FileNotFoundError as err:
        print("pcap file was not found")
        sys.exit(2)
    
    packets = removeOtherPackets(packets, IPAddr)
    # for ind, packet in enumerate(packets):
    #     if (packet.getlayer(IP).dst == IPAddr) and (not packet.getlayer(TCP).flags == ACK):
    #         ackdPacketNum = findAck(packet, packets)
    #         print("Packet {:>3} is ack'd at packet {:>3}".format(ind, ackdPacketNum) )

    statistics(packets, IPAddr, fileName)





if __name__ == "__main__":
    main()
