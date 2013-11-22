import random
import string
import socket

def getNextTTL():
	return 5

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
	port = 50254
	while True:
		# set up sockets
		sendSock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		icmpSock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
			socket.IPPROTO_ICMP)
		ttl = getNextTTL()
		sendSock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

		# send a short message to the destination
		identifier = getRandomId()
		sendSock.sendto(identifier, (dest_addr, port))
		
		icmp_data = icmpSock.recv(512)
		extractICMP(icmp_data)
		# print icmp_data

		sendSock.close()
		icmpSock.close()
		break

if __name__ == '__main__':
	main("google.com")
