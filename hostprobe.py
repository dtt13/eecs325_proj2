import select
import socket

class Probe(object):
	"""docstring for Probe"""
	def __init__(self, dest_host):
		self.dest_addr = socket.gethostbyname(dest_host)
		self.dest_port = 33465
		ttl = 16

	def sendMessage(self):
		# create a socket
		sendSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		sendSock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
		# send a short message to the destination
		message = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		sendSock.sendto(message, (dest_addr, dest_port))
		sendSock.close()

	def getResponse(self):
		# create a socket
		icmpSock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
		# capture a response
		icmp_rsp = ''
		rlist, wlist, elist = select.select([icmpSock], [], [], 3000)
		for socket in rlist:
			if socket is icmpSock:
				icmp_rsp = icmpSock.recv(512)
				# (icmp_type, icmp_code) = getTypeCode(icmp_rsp)
				# ttl = getNextTTL(ttl, icmp_type, icmp_code)
		icmpSock.close()
		return icmp_rsp

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
	print "%d, %d" % (icmp_type, icmp_code)
	return (icmp_type, icmp_code)

def getRouterIP(icmp_rsp):
	offset = 12
	router_ip = "%d.%d.%d.%d" % (ord(icmp_rsp[offset]), ord(icmp_rsp[offset+1]), ord(icmp_rsp[offset+2]), ord(icmp_rsp[offset+3]))
	return router_ip

def getDest(icmp_rsp):
	offset = 44
	dest_ip = "%d.%d.%d.%d" % (ord(icmp_rsp[offset]), ord(icmp_rsp[offset+1]), ord(icmp_rsp[offset+2]), ord(icmp_rsp[offset+3]))
	dest_port = ord(icmp_rsp[offset+6:offset+7])
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
	print "dest ip, dest port"
	print "%s, %d" % getDest(response)
	# if min_ttl == max_ttl - 1:
	break
#print ttl + 1
