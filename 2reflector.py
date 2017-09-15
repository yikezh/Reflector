#!/usr/bin/env
import sys
import getopt
from scapy.all import *
#define a function called getPacket
def getPacket(pckt):
	#pckt.show()
	try:
		if pckt.haslayer(ARP): 
			#pckt.show()
			#if the attacker sent an ARP request to the victim
			if pckt[ARP].pdst == reflectorIp:
				pckt
				pckt.command()
				#pckt.show()
				#dst becomes attacker's
				pckt[Ether].dst = pckt[Ether].src 
				pckt[ARP].pdst = pckt[ARP].psrc
				pckt[ARP].hwdst = pckt[ARP].hwsrc
				#src becomes reflector's
				pckt[Ether].src = reflectorEthernet
				pckt[ARP].hwsrc = reflectorEthernet
				pckt[ARP].psrc = reflectorIp
				#type changes to 2 "it-at"
				pckt[ARP].op = 2
				print "ARP request to attacker from reflector"
				pckt
				sendp(pckt)
				pckt.show()
			#if the attacker sent an ARP response to the reflector
			elif pckt[ARP].pdst == victimIp:
				pckt.show()
				arppkt = eval(pckt.command())
				attackerEther = arppkt[Ether].src
				#dst becomes attacker's
				arppkt[Ether].dst = arppkt[Ether].src 
				arppkt[ARP].pdst = arppkt[ARP].psrc
				arppkt[ARP].hwdst = arppkt[ARP].hwsrc
				#src becomes victim's
				arppkt[Ether].src = victimEthernet
				arppkt[ARP].hwsrc = victimEthernet
				arppkt[ARP].psrc = victimIp
				#type changes to 2 "it-at"
				arppkt[ARP].op = 2
				print "ARP response to attacker as if it is from the victim"
				arppkt.show()
				sendp(arppkt)
		#print victimIp
		#print pckt[IP].dst
		#if the packet is sent to victim IP
		elif pckt.haslayer(IP):
			
			if pckt[IP].dst == victimIp:
				pckt.show()
				#change the destination IP&Ether to the attacker
				attackerIP = pckt[IP].src
				pckt[IP].dst = attackerIP
				attackerEther = pckt[Ether].src
				pckt[Ether].dst = attackerEther
				#change the source IP&Ether to the reflector
				pckt[IP].src = reflectorIp
				pckt[Ether].src = reflectorEthernet
				print "This is a PACKET. scr is reflector"
				#delete checksum of the packet
				del pckt.chksum
				if pckt.haslayer(TCP):
					del pckt[TCP].chksum
				elif pckt.haslayer(UDP):
					del pckt[UDP].chksum
				elif pckt.haslayer(ICMP):
					del pckt[ICMP].chksum
				pckt.show2()
				sendp(pckt, iface=interface)
				pckt.show()
			#if the packet is sent to reflector IP
			elif pckt[IP].dst == reflectorIp:
				pckt.show()
				#change the destination IP&Ether to the attacker
				attackerIP = pckt[IP].src
				pckt[IP].dst = attackerIP
				attackerEther = pckt[Ether].src
				pckt[Ether].dst = attackerEther
				#change the source IP&Ether to the victim
				pckt[IP].src = victimIp
				pckt[Ether].src = victimEthernet
				#delete checksum of the packet
				del pckt.chksum
				if pckt.haslayer(TCP):
					del pckt[TCP].chksum
				elif pckt.haslayer(UDP):
					del pckt[UDP].chksum
				elif pckt.haslayer(ICMP):
					del pckt[ICMP].chksum
				pckt.show2()
				print "This is a PACKET. scr is victim"
				#send the packet
				sendp(pckt, iface=interface)
				pckt.show2()
	except Exception as e:
		print e

#get the input from the command line
try:
	opts, args = getopt.getopt(sys.argv[1:], "",['interface=', 'victim-ip=', 'victim-ethernet=', 'reflector-ip=', 'reflector-ethernet='])
except getopt.GetoptError as e:
	print e

for opt, arg in opts:
	if opt in ('--interface'):
		interface = arg
	if opt in ('--victim-ip'):
		victimIp = arg
	if opt in ('--victim-ethernet'):
		victimEthernet = arg
	if opt in ('--reflector-ip'):
		reflectorIp = arg
	if opt in ('--reflector-ethernet'):
		reflectorEthernet = arg
sniff(iface = interface, prn = getPacket)
# p=sniff(count=3, filter = "arp")
# p.summary()

#packets.summary()
#print victimEthernet 
