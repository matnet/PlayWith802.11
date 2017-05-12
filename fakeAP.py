#!/usr/bin/env python

import sys
from scapy import *

interface = sys.argv[1]   
ssid = "'"+sys.argv[2]+"'"
mac = sys.argv[3]

def monitorSSID(p):      
     if p.haslayer(Dot11Beacon):        
          pssid = p.sprintf("%Dot11Elt.info%")
          pmac = p.sprintf("%Dot11.addr2%")
          if(ssid == pssid):  			
               if not (pmac==mac):
                    print "Dummy AP found -> "+pmac      

sniff(iface=interface,prn=monitorSSID)
