import select
import socket
import sys
import random
import struct
import time

class Probe(object):
	msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	timeout = 3 # seconds
	ttl = 16
	max_ttl = 'inf' 
	min_ttl = 0
	timer = 0
	rtt = 0
	dest_port = 33434	

	"""probes a specified host"""
	def __init__(self, dest_host):
		self.dest_addr = socket.gethostbyname(dest_host)
		if not self.isValid():
			print "could not identify host %s" % (dest_host)
			sys.exit()
		self.icmpSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

	# checks if the destination is a valid IP address
	def isValid(self):
		try:
			socket.inet_aton(self.dest_addr)
		except socket.error:
			return False
		return True

	# sends a short UDP message
	def sendMessage(self):
		# setup sending socket
		sendSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
		packet = self.generateIpHeader() + self.generateUdpHeader() + self.msg
		# send a short message to the destination
		self.timer = time.time()
		try:
			sendSock.sendto(packet, (self.dest_addr, self.dest_port))
		except socket.error:
			print "socket unavailable for sending"
			sys.exit()
		sendSock.close()

	# checks the ICMP socket listener for a response and captures it if available
	# may timeout without a response
	def getResponse(self):
		icmp_rsp = ''
		(icmp_type, icmp_code) = (-1, -1)
		rlist, wlist, elist = select.select([self.icmpSock], [], [], self.timeout)
		for skt in rlist:
			if skt is self.icmpSock:
				icmp_rsp = extractIcmpResponse(self.icmpSock.recv(512))
				if self.isMatch(icmp_rsp):
					self.timer = time.time() - self.timer
					(icmp_type, icmp_code) = getTypeCode(icmp_rsp)
		self.getNextTTL(icmp_type, icmp_code)
		return icmp_rsp

	# returns true if ID of response matches that of the ID sent; false otherwise
	def isMatch(self, icmp_rsp):
		return (getIpIdentification(icmp_rsp) == self.ip_id)

	# updates the TTL of the probe object
	def getNextTTL(self, icmp_type, icmp_code):
		if self.max_ttl == 'inf':
			if icmp_type == 3: # too long
				self.max_ttl = self.ttl
				self.ttl = (self.max_ttl + self.min_ttl) / 2
				self.rtt = self.timer
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
				self.rtt = self.timer
			elif icmp_type == 11 and icmp_code == 0: # too short
				self.min_ttl = self.ttl
				self.ttl = (self.max_ttl + self.min_ttl) / 2
			else: # timeout or other response
				self.ttl *= 2
				self.min_ttl += 1
	
	# creates a custom IP header with specific TTL and random ID
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

	# creates a simple UDP header from a random port
	def generateUdpHeader(self):
		udp_src = random.randint(33000, 55000)
		udp_dest = self.dest_port
		udp_total_length = 8 + len(self.msg)
		udp_checksum = 0
		udp_header = struct.pack('!HHHH', udp_src, udp_dest, udp_total_length, udp_checksum)
		return udp_header

	def close(self):
		self.icmpSock.close()

# returns the ICMP response within the IP frame
def extractIcmpResponse(response):
	return response[20:]

# determines the ICMP type and code
def getTypeCode(icmp_rsp):
	offset = 0
	icmp_type = ord(icmp_rsp[offset])
	icmp_code = ord(icmp_rsp[offset+1])
	return (icmp_type, icmp_code)

# determines the ID from the IP header of the ICMP response
def getIpIdentification(icmp_rsp):
	offset = 12
	ident = (ord(icmp_rsp[offset]) << 8)  + ord(icmp_rsp[offset+1])
	return ident

# prints the ICMP type and code
def printResponse(response):
	if response != '':
		print "type, code:"
		print "%d, %d" % getTypeCode(response)

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
	if probe.ttl > 64: # too many timeouts
		print "host could not be reached"
		break
	if probe.max_ttl != 'inf' and probe.min_ttl == probe.max_ttl - 1:
		print "hops: %d" % (probe.max_ttl)
		print "RTT: %.3f ms" % (probe.rtt * 1000)
		break
probe.close()
