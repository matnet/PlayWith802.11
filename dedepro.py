# Rewritten by Matnet
# Email : mail@matnet.my
# Please run monitore mode first before run the program
# Usage : python dedepro.py mon0 legit-AP AP-MAC
# Original Script by : Ajay

import sys
import datetime
import scapy
from scapy.all import *

APtipuThresold = 4
global simpanMasa
global kiraMasa
kiraDeauth=0
deauthThreshold=4
MULA=5

# Detect fake AP by randomly compairing timestamp field and maintain the counts
def PantauAPtipu(pkt):
    global simpanMasa
    global kiraMasa
    global APtipuThresold
    if(pkt.type==0 and pkt.subtype==8):
        ssid=pkt.info
        bssid=pkt.addr2
        timestamp=pkt.timestamp
        if bssid not in simpanMasa:
            simpanMasa[bssid]=timestamp
            kiraMasa[bssid]=0
        elif (timestamp <= simpanMasa[bssid]):
            kiraMasa[bssid]+=1
            if kiraMasa[bssid] > APtipuThresold :
                print "Fake Access Point dikesan dengan menggunakan ssid '%s'"%(ssid)
        simpanMasa[bssid]=timestamp

#  Detect fake AP by capturing packets and comparing their MAC addresses with authorized MAC addresses
def PantauAPtipu2(pkt):
    if pkt.haslayer(Dot11Beacon):
        pssid = pkt.sprintf("%Dot11Elt.info%")
        pmac = pkt.sprintf("%Dot11.addr2%")
        if(ssid == pssid):
            if not (pmac==mac):
                print "Evil Twin AP dijumpai -> "+pmac



# Detect de-auth attack by continuosly count of the packet
def pantauDeauth(pkt):
    global kiraDeauth
    if((pkt.type==0) and (pkt.subtype==12)):
        kiraDeauth+=1
        beza = datetime.datetime.now()-mula
        if((beza.seconds > MULA) and ((kiraDeauth/beza.seconds) > deauthThreshold)):
           print "Detected De-authentication againts : "+pkt.addr1


# Maintain Radiotap header for each sender
def MaintainsimpanRadiotap(pkt):
    global simpanRadiotap
    if(pkt.getlayer(Dot11).type==2):
        radiotap=str(pkt)[:pkt.getlayer(RadioTap).len]
        sender=pkt.getlayer(Dot11).addr2
        if sender not in simpanRadiotap:
            simpanRadiotap[sender]=radiotap
           

        
# Monitor changes in radiotap header in de-auth packets
def pantauDeauth2(pkt):
    sender=pkt.getlayer(Dot11).addr2
    radiotap=str(pkt)[:pkt.getlayer(RadioTap).len]
    if sender in simpanRadiotap:
        radiotap2=simpanRadiotap[sender]
        if radiotap2!=radiotap:
            print "Detected De-auth against : %s by change in radiotap header"%(pkt.getlayer(Dot11).addr1)
	script = subprocess.call("python alert.py",shell=True)
            

def dedepro(pkt):
    if(pkt.haslayer(Dot11)):
        if(pkt.getlayer(Dot11).type==2):
            MaintainsimpanRadiotap(pkt)
            PantauAPtipu2(pkt)
        if((pkt.getlayer(Dot11).type==0) and (pkt.getlayer(Dot11).subtype==12)):
            pantauDeauth(pkt.getlayer(Dot11)) # detect for de-auth attack
            pantauDeauth2(pkt) # detect for deauth attack by monitoring change in radiotap header
        if(pkt.getlayer(Dot11).type==0 and pkt.getlayer(Dot11).subtype==8):
            PantauAPtipu(pkt.getlayer(Dot11)) # detect fake AP





simpanMasa= {}
kiraMasa={}
simpanRadiotap={}
mula=datetime.datetime.now()
ssid = "'"+sys.argv[2]+"'"
mac = sys.argv[3]
sniff(iface=sys.argv[1],prn=dedepro)


