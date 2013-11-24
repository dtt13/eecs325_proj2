import select
import socket

class Probe(object):
	"""docstring for Probe"""
	def __init__(self, dest_host):
		self.dest_addr = socket.gethostbyname(dest_host)
		self.dest_port = 33465
		self.sendSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.icmpSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		self.ttl = 16
		self.max_ttl = 'inf'
		self.min_ttl = 0

	def sendMessage(self):
		# setup sending socket
		self.sendSock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
		# send a short message to the destination
		message = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		self.sendSock.sendto(message, (self.dest_addr, self.dest_port))

	def getResponse(self):
		# capture a response
		icmp_rsp = ''
		(icmp_type, icmp_code) = (3, 0)
		rlist, wlist, elist = select.select([self.icmpSock], [], [], 3)
		for skt in rlist:
			if skt is self.icmpSock:
				icmp_rsp = self.icmpSock.recv(512)
				if self.isMatch(icmp_rsp):
					(icmp_type, icmp_code) = getTypeCode(icmp_rsp)
		self.getNextTTL(icmp_type, icmp_code)
		return icmp_rsp

	def isMatch(self, icmp_rsp):
		return (getDest(icmp_rsp) == (self.dest_addr, self.dest_port))

	def getNextTTL(self, icmp_type, icmp_code):
		if self.max_ttl == 'inf':
			if icmp_type == 3 and icmp_code == 3: # too long
				self.max_ttl = self.ttl
				self.ttl = (self.max_ttl + self.min_ttl) / 2
			elif icmp_type == 11 and icmp_code == 0: # too short
				self.min_ttl = self.ttl
				self.ttl *= 2
			else: # timeout or other response
				self.ttl *= 2
		else:	
			if icmp_type == 3 and icmp_code == 3: # too long
				self.max_ttl = self.ttl
				self.ttl = (self.max_ttl + self.min_ttl) / 2
			elif icmp_type == 11 and icmp_code == 0: # too short
				self.min_ttl = self.ttl
				self.ttl = (self.max_ttl + self.min_ttl) / 2
			else: # timeout or other response
				self.ttl *= 2

	def close(self):
		self.sendSock.close()
		self.icmpSock.close()

def getIPHeaderLength(icmp_rsp):
	length = (ord(icmp_rsp[0]) & 0x0F) * 4
	return length

def getTypeCode(icmp_rsp):
	offset = getIPHeaderLength(icmp_rsp)
	icmp_type = ord(icmp_rsp[offset])
	icmp_code = ord(icmp_rsp[offset+1])
	return (icmp_type, icmp_code)

def getRouterIP(icmp_rsp):
	offset = 12 # src in ip header
	router_ip = "%d.%d.%d.%d" % (ord(icmp_rsp[offset]), ord(icmp_rsp[offset+1]), ord(icmp_rsp[offset+2]), ord(icmp_rsp[offset+3]))
	return router_ip

def getDest(icmp_rsp):
	offset = 44
	dest_ip = "%d.%d.%d.%d" % (ord(icmp_rsp[offset]), ord(icmp_rsp[offset+1]), ord(icmp_rsp[offset+2]), ord(icmp_rsp[offset+3]))
	dest_port = ord(icmp_rsp[offset+6])*256 + ord(icmp_rsp[offset+7])
	return (dest_ip, dest_port)

probe = Probe("yahoo.com")
while True:
	print "max_ttl: %s   min_ttl: %s  ttl: %s" % (probe.max_ttl, probe.min_ttl, probe.ttl)
	# set up sockets
	probe.sendMessage()
	response = probe.getResponse()
	if response != '':
		print "router ip:"
		print getRouterIP(response)
		print "type, code:"
		print "%d, %d" % getTypeCode(response)
		print "dest ip, dest port:"
		print "%s, %d" % getDest(response)
		print
	if probe.ttl > 64:
		print "host was unreachable"
		break
	if probe.max_ttl != 'inf' and probe.min_ttl == probe.max_ttl - 1:
		print "hops: %d" % probe.ttl + 1
		break
probe.close()
