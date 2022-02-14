import socket 
import ssl


def map4to6(ip):
	return "::ffff:"+ip


def prefixstream(pkt):
	tcpkt = bytearray()
	tcpkt.append(len(pkt)//0x100)
	tcpkt.append(len(pkt)%0x100)
	tcpkt += pkt
	return tcpkt


def getfromstream(sock):
	data = sock.recv(0x2)
	l = data[0] * 0x100
	l += data[1]
	data = sock.recv(l)
	return data


def udprequest(pkt, ipv6, port=53, timeout=None):
	sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
	sock.settimeout(timeout)
	sock.sendto(pkt, (ipv6, port))
	data = sock.recv(0xFFFF)
	return data


def tcprequest(pkt, ipv6, port=53, timeout=None):
	sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
	sock.settimeout(timeout)
	sock.connect((ipv6, port))
	tcpkt = prefixstream(pkt)
	sock.sendall(tcpkt)
	return getfromstream(sock)


def tlswrap(sock, verify, hostname):
	context = ssl.create_default_context()

	if verify:
		try:
			if not hostname.index("::ffff:"): hostname = hostname[7:] #convert ipv6 mapped ipv54 adress for hostname (if map4to6 format is used)
		except ValueError: #not found
			pass

		context.check_hostname = True
		context.verify_mode = ssl.CERT_REQUIRED
		wrap = context.wrap_socket(sock, server_hostname=hostname)
	else:
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		wrap = context.wrap_socket(sock)

	return wrap

#RFC 7858
def tlsrequest(pkt, ipv6, port=853, timeout=None, verify=True, hostname=None):
	if not hostname: hostname = ipv6
	tcpsock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
	tcpsock.settimeout(timeout)
	tcpsock.connect((ipv6, port))
	sock = tlswrap(tcpsock, verify, hostname)
	tcpkt = prefixstream(pkt)
	sock.sendall(tcpkt)
	return getfromstream(sock)

#RFC 8484
#POST is shorter, so doing that
#TODO: content-length & chunking
def dohrequest(pkt, ipv6, port=443, timeout=None, verify=True, hostname=None):
	if not hostname: hostname = ipv6
	tcpsock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
	tcpsock.settimeout(timeout)
	tcpsock.connect((ipv6, port))
	sock = tlswrap(tcpsock, verify, hostname)

	httphostname = hostname
	try:
		if not httphostname.index("::ffff:"): httphostname = httphostname[7:] #convert ipv6 mapped ipv54 adress for hostname (if map4to6 format is used)
	except ValueError:
		pass
	if ":" in httphostname: httphostname = "[{}]".format(httphostname)

	#now wrap in HTTP/1.1
	http = bytearray()
	http += b"POST /dns-query HTTP/1.1\r\n"
	http += b"Host: "
	http += httphostname.encode('ASCII')
	http += b"\r\nAccept: application/dns-message\r\n"
	http += b"Content-Type: application/dns-message\r\n"
	http += b"Content-Length: "
	http += str(len(pkt)).encode('ASCII')
	http += b"\r\n\r\n"
	http += pkt

	sock.sendall(http)
	httpdata = sock.recv(0xFFFF)
	index = httpdata.find(b'\r\n\r\n')
	return httpdata[index+4:]
	
