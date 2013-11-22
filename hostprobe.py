
import socket

def getNextTTL():
	return 3

def main(dest_host):
	dest_addr = gethostbyname(dest_host)
	port = 50254
	while True:
		# set up sockets
		sendSock = socket.socket(socket.AF_INET, socket.DGRAM)
		icmpSock = socket.socket(socket.AF_INET, socket.RAW,
			socket.IPPROTO_ICMP)
		ttl = getNextTTL()
		sendSock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

		# send a short message to the destination
		sendSock.sendto("hello world", (dest_addr, port))

		sendSock.close()
		icmpSock.close()
		break

if __name__ == '__main__':
	main("google.com")