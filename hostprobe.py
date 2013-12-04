import select
import socket
import sys
import random
import struct
import time

class Probe(object):
	msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	ttl = 1
	max_ttl = 4 
	min_ttl = 0
	timer = 0

	"""probes a specific host"""
	def __init__(self, dest_host):
		self.dest_addr = socket.gethostbyname(dest_host)
		self.dest_port = random.randint(16000, 56000)
		self.icmpSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

	def sendMessage(self):
		# setup sending socket
		sendSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
		message = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		packet = self.generateIpHeader() + self.generateUdpHeader() + message
		# send a short message to the destination
		self.timer = time.time()
		sendSock.sendto(packet, (self.dest_addr, self.dest_port))
		sendSock.close()

	def getResponse(self):
		# capture a response
		icmp_rsp = ''
		(icmp_type, icmp_code) = (0, 0)
		rlist, wlist, elist = select.select([self.icmpSock], [], [], 3)
		for skt in rlist:
			if skt is self.icmpSock:
				icmp_rsp = self.icmpSock.recv(512)
				if self.isMatch(icmp_rsp):
					self.timer = time.time() - self.timer
					(icmp_type, icmp_code) = getTypeCode(icmp_rsp)
		self.getNextTTL(icmp_type, icmp_code)
		return icmp_rsp

	def isMatch(self, icmp_rsp):
		return (getIpIdentification(icmp_rsp) == self.ip_id)

	def getNextTTL(self, icmp_type, icmp_code):
		self.ttl += 1
		self.min_ttl = self.ttl
		"""
		if self.max_ttl == 'inf':
			if icmp_type == 3: # too long
				self.max_ttl = self.ttl
				self.ttl = (self.max_ttl + self.min_ttl) / 2
			elif icmp_type == 11 and icmp_code == 0: # too short
				self.min_ttl = self.ttl
				self.ttl *= 2
			else: # timeout or other response
				self.ttl *= 2
				self.min_ttl += 1
		else:	
			if icmp_type == 3: # too long
				self.max_ttl = self.ttl
				self.ttl = (self.max_ttl + self.min_ttl) / 2
			elif icmp_type == 11 and icmp_code == 0: # too short
				self.min_ttl = self.ttl
				self.ttl = (self.max_ttl + self.min_ttl) / 2
			else: # timeout or other response
				self.ttl *= 2
				self.min_ttl += 1"""
	
	def checksum(self, data):
		check = 0
		for i in range(0, len(data), 2):
			check += ord(data[i]) + (ord(data[i+1]) << 8)
		check = (check >> 16) + (check & 0xffff)
		check = check + (check >> 16)
		check = ~check & 0xffff
		return check
	
	def generateIpHeader(self):
		ip_ihl_ver = (4 << 4) + 5
		ip_tos = 0
		ip_total_length = 0
		self.ip_id = random.randint(1, 65535) # 16 bit id
		ip_frag_off = 0
		ip_protocol = socket.IPPROTO_UDP
		ip_checksum = 0
		ip_src = socket.inet_aton('0.0.0.0')
		ip_dest = socket.inet_aton(self.dest_addr)
		ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_total_length, self.ip_id, ip_frag_off, self.ttl, ip_protocol, ip_checksum, ip_src, ip_dest)
		return ip_header

	def generateUdpHeader(self):
		udp_src = random.randint(33000, 55000)
		udp_dest = self.dest_port
		udp_total_length = 8 + len(self.msg)
		udp_checksum = 0
		udp_header = struct.pack('!HHHH', udp_src, udp_dest, udp_total_length, udp_checksum)
		# udp_checksum = self.checksum(self.msg)
		# udp_header = struct.pack('!HHHH', udp_src, self.dest_port, udp_total_length, udp_checksum)
		return udp_header

	def close(self):
		self.icmpSock.close()

def getIPHeaderLength(icmp_rsp):
	length = (ord(icmp_rsp[0]) & 0x0F) * 4
	return length

def getTypeCode(icmp_rsp):
	offset = getIPHeaderLength(icmp_rsp)
	icmp_type = ord(icmp_rsp[offset])
	icmp_code = ord(icmp_rsp[offset+1])
	return (icmp_type, icmp_code)

def getIpIdentification(icmp_rsp):
	offset = 32
	ident = (ord(icmp_rsp[offset]) << 8)  + ord(icmp_rsp[offset+1])
	return ident

def getRouterIP(icmp_rsp):
	offset = 12 # src in ip header
	router_ip = "%d.%d.%d.%d" % (ord(icmp_rsp[offset]), ord(icmp_rsp[offset+1]), ord(icmp_rsp[offset+2]), ord(icmp_rsp[offset+3]))
	return router_ip

def printResponse(response):
	if response != '':
		print "router ip:"
		print getRouterIP(response)
		print "type, code:"
		print "%d, %d" % getTypeCode(response)
		print
def usage():
	print "Please use the following instruction to run HostProbe"
	print "python hostprobe.py [host]"

if len(sys.argv) != 2:
	usage()
	sys.exit()
print "scanning %s..." % sys.argv[1]
probe = Probe(sys.argv[1])
while True:
	print "max_ttl: %s   min_ttl: %s  ttl: %s" % (probe.max_ttl, probe.min_ttl, probe.ttl)
	probe.sendMessage()
	response = probe.getResponse()
	printResponse(response)
	if probe.ttl > 64:
		print "host was unreachable"
		break
	if probe.max_ttl != 'inf' and probe.min_ttl == probe.max_ttl - 1:
		print "hops: %d" % (probe.max_ttl)
		print "RTT: %.3f ms" % (probe.timer * 1000)
		break
probe.close()
