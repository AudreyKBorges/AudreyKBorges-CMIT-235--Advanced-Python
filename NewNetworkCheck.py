# Audrey Borges
# October 10, 2021
# CMIT-235-40 Advanced Python
# Week 6: Assignment - Exception Handling

import numpy as np
from scapy.all import *
import CMIT235_Package.CMIT235_Tools as cm
from CMIT235_Package.NetworkCheck import NetworkCheck


class NewNetworkCheck(NetworkCheck):
    def __init__(self):
        NetworkCheck.__init__(self)
        # Dictionary with all three lists as input consisting of
        # the number of dimensions, shape, mean, median, and standard deviation.

    def getDescriptiveInfo(self, *args):
        myDict = {}
        count = 1

        for i in args:
            arr1 = np.array(i)
            strCount = str(count)
            myDict["Dimension" + strCount] = arr1.ndim
            myDict["Shape" + strCount] = arr1.shape
            myDict["Mean" + strCount] = np.mean(arr1)
            myDict["Median" + strCount] = np.median(arr1)
            myDict["Standard Deviation" + strCount] = np.std(arr1)
            count += 1
        return myDict


class AddedNetworkCheck(NewNetworkCheck):

    def __init__(self):
        NewNetworkCheck.__init__(self)

    def getPingCount(self, packets):
        for packet in packets:
            if packet.haslayer(TCP) and packet[TCP].window == 65535:
                print(packets)
