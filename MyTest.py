# Audrey Borges
# October 10, 2021
# CMIT-235-40 Advanced Python
# Week 6: Assignment - Exception Handling

import sys

import dictionary as dictionary
import numpy as np
import pandas as pd
from numpy import ndarray
from scapy.error import Scapy_Exception
from scapy.utils import rdpcap
import CMIT235_Package.CMIT235_Tools as cm
import CMIT235_Package.NetworkCheck as nc
import CMIT235_Package.NewNetworkCheck as nnc
from CMIT235_Package.NewNetworkCheck import NewNetworkCheck
import logging
logging.basicConfig(filename='CMIT235_MyLog.log', level=logging.DEBUG)
logging.info('This is the start of the program.')

# Check that all three sublists are list type

if not type(cm.mySubList1) is list:
    print('The result must be a list. mySubList1 is not a list.')
else:
    print('mySubList1 is a list.')
    logging.error('Program error at line 25.')

if not type(cm.mySubList2) is list:
    print('The result must be a list. mySubList2 is not a list.')
else:
    print('mySubList2 is a list.')
    logging.error('Program error at line 25.')

if not type(cm.mySubList3) is list:
    print('The result must be a list. mySubList3 is not a list.')
else:
    print('mySubList3 is a list.')
    logging.error('Program error at line 25.')

# 3 lists combined into one

myList = cm.mySubList1 + cm.mySubList2 + cm.mySubList3
print('Combined Lists: ', myList)

try:
    myNpArray = np.array(myList)  # List converted to np.array
    print('The lowest value is: ', np.min(myNpArray))
    print('The highest value is: ', np.max(myNpArray))
    print('The unique list is: ', np.unique(myNpArray))
except ValueError:
    print("ValueError exception thrown")
    logging.error("ValueError exception thrown")
    sys.exit(1)
except TypeError:
    print("TypeError exception thrown")
    logging.error("TypeError exception thrown")
    sys.exit(2)

if np.min(myNpArray) > 100:
    raise ValueError

if np.max(myNpArray) < 0:
    raise ValueError

if not type(np.unique(myNpArray)) is ndarray:
    print('Unique values is not an ndarray.')
    sys.exit(3)
else:
    print('Unique values is an ndarray.')
    logging.error('MyTest program error at line 64.')

for i in (cm.mySubList1, cm.mySubList2, cm.mySubList3):
    print(myList)
    print('Dimensions: ', myNpArray.ndim, 'Shape: ', myNpArray.shape)  # Dimensions, shape
    print('Last number: ', myNpArray[1, -1], 'Column 0: ', myNpArray[:, 0], 'Second row: ',
          myNpArray[1, :])  # Last number, column 0, second row

    if not type(cm.mySubList1) is ndarray:
        print('mySubList1 is not an ndarray.')
        sys.exit(4)
    if not type(cm.mySubList2) is ndarray:
        print('mySubList2 is not an ndarray.')
        sys.exit(5)
    if not type(cm.mySubList3) is ndarray:
        print('mySubList3 is not an ndarray.')
        sys.exit(6)

logging.info('This is the network check area.')

# Check to see if NetworkCheck object is correct
try:
    x = nc.NetworkCheck()
    check = isinstance(x, nc.NetworkCheck)
    myNpArray = x.convertList2NpArray(myList)
    print(myNpArray)
except:
    logging.error("NetworkCheck object is not correct.")
    sys.exit(7)

if min(x) > 100:
    raise ValueError

if max(x) < 0:
    raise ValueError

if not type(np.unique(x)) is ndarray:
    print('Unique values is not an ndarray.')
    sys.exit(8)

if not type(np.myDict(ndarray)) is ndarray:
    raise ValueError

# Directly get the private message1 attribute
try:
    message1 = x.message1
except:
    print("Unable to get message1")

# Directly get the private message2 attribute
try:
    message2 = x.message2
except:
    print("Unable to get message2")

# Getter method for message3
def getMessage3():
    pass


# Read in the packet capture file using the pcap constant
packets = rdpcap(cm.pcap)

# Call the get_spoofed_mac_count method to get the spoofed mac count.
mac_spoof_count = x.getSpoofedMacCount(packets, cm.spoofed_mac)
print("-----------------------Spoofed Mac count is-------------------------------")
print(mac_spoof_count)
if not type(mac_spoof_count) is int:
    print('Spoofed mac count is not an integer.')
    sys.exit(9)
# Get the port count by calling the get_port_count getter method
port_count = x.getPortCount(packets, cm.port)
print("-----------------------Port count is-------------------------------")
print(port_count)
if not type(port_count) is int:
    print('Port count is not an integer.')
    sys.exit(10)

# Three messages on one line using f-strings right justified
print(f"{str(x.getMessage1()):>25} {str(x.getMessage2())} {str(x.message3)}")

# Week 4
# Call the checkCounts method using the csv_data file and feature3 and print the result.
try:
    df = pd.read_csv(cm.csv_data, sep=',', decimal='.', header=0)
except Scapy_Exception:
    print('Cannot open csv_data file.')
    sys.exit(11)

sep = '-' * 40

try:
    y = isinstance(NewNetworkCheck())
    print(sep)
    y.getDescriptiveInfo()
except:
    logging.error("NewNetworkCheck object is not correct.")
    sys.exit(12)

try:
    print("-----------------------Protocol count is-------------------------------")
    print(df[cm.feature3].value_counts())
except:
    print('Cannot get protocol count.')
    sys.exit(13)

# Get the list counts in a dictionary and print source and destination IP counts
d = x.checkCounts(cm.csv_data, cm.feature1, cm.feature2, cm.feature3)
if not type(d) is dictionary:
    raise ValueError

print("-----------------------Source IP count is-------------------------------")
print(d[cm.feature1])
print("-----------------------Destination IP count is-------------------------------")
print(d[cm.feature2])

# Use overloaded checkCounts for all features and print the highest one
result = x.checkCounts(cm.csv_data, cm.feature1, cm.feature2, cm.feature3, cm.feature4, cm.feature5)
try:
    print(result)
except:
    print("Cannot get result.")
    sys.exit(14)

# Week 5
y.convertList2NpArray(myList)
y.getMin(myList)
y.getMax(myList)
y.getUniqueValues(myList)

try:
    z = isinstance(nnc.AddedNetworkCheck())
except:
    logging.error("AddedNetworkCheck object is not correct.")
    sys.exit(15)

logging.info('Created AddedNetworkCheck object.')

z.getSpoofedMacCount(cm.pcap, cm.spoofed_mac)
z.getPingCount(packets)
nc.checkCounts(cm.feature3)








