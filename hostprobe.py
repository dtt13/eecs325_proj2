import random
import string
import socket

max_ttl = 32
min_ttl = 0

def getNextTTL(ttl, icmp_type, icmp_code):
	global max_ttl, min_ttl
	if icmp_type == 3 and icmp_code == 3: # too long
		max_ttl = ttl
	elif icmp_type == 11 and icmp_code == 0: # too short
		min_ttl = ttl
	return (min_ttl + max_ttl) / 2

def getRandomId():
	return ''.join(random.choice(string.lowercase) for i in range(32))

def extractICMP(icmp_rsp):
	icmp_type = ord(icmp_rsp[20])
	icmp_code = ord(icmp_rsp[21])
	icmp_src = "%d.%d.%d.%d" % (ord(icmp_rsp[12]), ord(icmp_rsp[13]),
		ord(icmp_rsp[14]), ord(icmp_rsp[15]))
	icmp_data = icmp_rsp[56:]
	print "%d, %d src: %s" % (icmp_type, icmp_code, icmp_src)
	print icmp_data
	return (icmp_type, icmp_code, icmp_src, icmp_data)

def main(dest_host):
	dest_addr = socket.gethostbyname(dest_host)
	port = 33465
	ttl = 16
	while ttl <= 64:
		print "max_ttl: %s   min_ttl: %s  ttl: %s" % (max_ttl, min_ttl, ttl)
		# set up sockets
		sendSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		icmpSock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
			socket.IPPROTO_ICMP)
		sendSock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

		# send a short message to the destination
		identifier = getRandomId()
		sendSock.sendto(identifier, (dest_addr, port))
		
		icmp_rsp = icmpSock.recv(512)
		(icmp_type, icmp_code, icmp_src, icmp_data) = extractICMP(icmp_rsp)
	#	if icmp_data == identifier: # icmp message is from udp msg
		ttl = getNextTTL(ttl, icmp_type, icmp_code)
		
		sendSock.close()
		icmpSock.close()
		
		if min_ttl == max_ttl - 1:
			break
	print ttl + 1

if __name__ == '__main__':
	main("yahoo.com")
