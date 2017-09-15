#!/usr/bin/python
import sys
import getopt
import traceback
from scapy.all import *
inter=0

def reflectorcallback(pkt):
	try:
		if ARP in pkt:
			if pkt[ARP].pdst == ipvic:
				#print("receive")
				arppkt = Ether(src = ethervic, dst = pkt[Ether].src) / ARP(op = 2, hwsrc = ethervic, psrc = ipvic, hwdst = pkt[ARP].hwsrc, pdst=pkt[ARP].psrc)
				#pkt.show()
				# pkt[ARP].hwdst = pkt[ARP].hwsrc
				# pkt[ARP].op = 2
				# pkt[ARP].hwsrc = ethervic
				# pkt[ARP].pdst = pkt[ARP].psrc
				# pkt[ARP].psrc = ipvic
				# pkt[Ether].dst = pkt[Ether].src
				# pkt[Ether].src = ethervic
				sendp(arppkt, iface = inter)
				#print("send")
				#pkt.show()

			elif pkt[ARP].pdst == iprefl:
				#print("receive")
				#pkt.show()
				arppkt = Ether(src = etherrefl, dst = pkt[Ether].src) / ARP(op = 2, hwsrc = etherrefl, psrc = iprefl, hwdst=pkt[ARP].hwsrc, pdst = pkt[ARP].psrc)
				# pkt[ARP].op = 2
				# pkt[ARP].hwdst = pkt[ARP].hwsrc
				# pkt[ARP].hwsrc = etherrefl
				# pkt[ARP].pdst = pkt[ARP].psrc
				# pkt[ARP].psrc = iprefl
				# pkt[Ether].dst = pkt[Ether].src
				# pkt[Ether].src = etherrefl
				sendp(arppkt, iface = inter)
				#print("send")
				#pkt.show()


		else:		
			if pkt[IP].dst == ipvic:
				#print("receive")
				#pkt.show()
				attackerIP = pkt[IP].src
				attackerEther = pkt[Ether].src
				pkt[Ether].dst = attackerEther
				pkt[Ether].src = etherrefl
				pkt[IP].dst = attackerIP
				pkt[IP].src = iprefl
				#print("send")
				del pkt.chksum
				if pkt.haslayer(TCP):
					del pkt[TCP].chksum
				elif pkt.haslayer(UDP):
					del pkt[UDP].chksum
				elif pkt.haslayer(ICMP):
					del pkt[ICMP].chksum
				pkt.show2()
				sendp(pkt, iface = inter)
				pkt.show2()
			
			

			elif pkt[IP].dst == iprefl:
				#print("receive")
				#pkt.show()
				attackerIP = pkt[IP].src
				attackerEther = pkt[Ether].src
				pkt[Ether].dst = attackerEther
				pkt[Ether].src = ethervic
				pkt[IP].dst = attackerIP
				pkt[IP].src = ipvic
				#print("send")
				del pkt.chksum
				if pkt.haslayer(TCP):
					del pkt[TCP].chksum
				elif pkt.haslayer(UDP):
					del pkt[UDP].chksum
				elif pkt.haslayer(ICMP):
					del pkt[ICMP].chksum
				pkt.show2()
				sendp(pkt, iface = inter)
				pkt.show2()
	except Exception as e:
		print(traceback.format_exc())
		print e			

#def reflectormain():
#	global ipvic, iprefl, ethervic, etherrefl
try:
	opts, args = getopt.getopt(sys.argv[1:], "",['interface=', 'victim-ip=', 'victim-ethernet=', 'reflector-ip=', 'reflector-ethernet='])
except getopt.GetoptError as e:
	print e
for o,a in opts :
	if o in ("--interface"):
		inf = a
	if o in ("--victim-ip"):
		ipvic = a
	if o in ("--victim-ethernet"):
		ethervic = a
	if o in ("--reflector-ip"):
		iprefl = a
	if o in ("--reflector-ethernet"):
		etherrefl = a
inter = inf
sniff(iface = inter, prn = reflectorcallback)

		#iface = inf, 
	
# if __name__ == '__main__':
# 	reflectormain()