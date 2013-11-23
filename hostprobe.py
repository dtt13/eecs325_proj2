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

	def sendMessage(self):
		# setup sending socket
		self.sendSock.setsockopt(socket.SOL_IP, socket.IP_TTL, self.ttl)
		# send a short message to the destination
		message = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		self.sendSock.sendto(message, (self.dest_addr, self.dest_port))

	def getResponse(self):
		# capture a response
		icmp_rsp = ''
		rlist, wlist, elist = select.select([self.icmpSock], [], [], 3000)
		for socket in rlist:
			if socket is self.icmpSock:
				icmp_rsp = self.icmpSock.recv(512)
				# (icmp_type, icmp_code) = getTypeCode(icmp_rsp)
				# ttl = getNextTTL(ttl, icmp_type, icmp_code)
		return icmp_rsp

	def close(self):
		self.sendSock.close()
		self.icmpSock.close()

max_ttl = 64
min_ttl = 0

def getNextTTL(ttl, icmp_type, icmp_code):
	global max_ttl, min_ttl
	if icmp_type == 3 and icmp_code == 3: # too long
		max_ttl = ttl
	elif icmp_type == 11 and icmp_code == 0: # too short
		min_ttl = ttl
	return (min_ttl + max_ttl) / 2

def getTypeCode(icmp_rsp):
	icmp_type = ord(icmp_rsp[20])
	icmp_code = ord(icmp_rsp[21])
	return (icmp_type, icmp_code)

def getRouterIP(icmp_rsp):
	offset = 12
	router_ip = "%d.%d.%d.%d" % (ord(icmp_rsp[offset]), ord(icmp_rsp[offset+1]), ord(icmp_rsp[offset+2]), ord(icmp_rsp[offset+3]))
	return router_ip

def getDest(icmp_rsp):
	offset = 44
	dest_ip = "%d.%d.%d.%d" % (ord(icmp_rsp[offset]), ord(icmp_rsp[offset+1]), ord(icmp_rsp[offset+2]), ord(icmp_rsp[offset+3]))
	dest_port = ord(icmp_rsp[offset+6])*256 + ord(icmp_rsp[offset+7])
	return (dest_ip, dest_port)

probe = Probe("google.com")
while probe.ttl <= 64:
	# print "max_ttl: %s   min_ttl: %s  ttl: %s" % (max_ttl, min_ttl, ttl)
	# set up sockets
	probe.sendMessage()
	response = probe.getResponse()
	print "router ip:"
	print getRouterIP(response)
	print "type, code:"
	print "%d, %d" % getTypeCode(response)
	print "dest ip, dest port:"
	print "%s, %d" % getDest(response)
	# if min_ttl == max_ttl - 1:
	break
#print ttl + 1
probe.close()
