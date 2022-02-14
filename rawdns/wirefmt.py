import random

### ### Tier 1 DNS functionality ### ### 

### Type defs ###

#See https://en.wikipedia.org/wiki/List_of_DNS_record_types
types = {
	"A": b"\x00\x01",
	"AAAA": b"\x00\x1c",
	"AFSDB": b"\x00\x12",
	"APL": b"\x00\x2a",
	"CAA": b"\x01\x01",
	"CDNSKEY": b"\x00\x3c",
	"CDS": b"\x00\x3b",
	"CERT": b"\x00\x25",
	"CNAME": b"\x00\x05",
	"CSYNC": b"\x00\x3e",
	"DHCID": b"\x00\x31",
	"DLV": b"\x80\x01",
	"DNAME": b"\x00\x27",
	"DNSKEY": b"\x00\x30",
	"DS": b"\x00\x2b",
	"EUI48": b"\x00\x6c",
	"EUI64": b"\x00\x6d",
	"HINFO": b"\x00\x0d",
	"HIP": b"\x00\x37",
	"HTTPS": b"\x00\x41",
	"IPSECKEY": b"\x00\x2d",
	"KEY": b"\x00\x19",
	"KX": b"\x00\x24",
	"LOC": b"\x00\x16",
	"MX": b"\x00\x0f",
	"NAPTR": b"\x00\x23",
	"NS": b"\x00\x02",
	"NSEC": b"\x00\x2f",
	"NSEC3": b"\x00\x32",
	"NSEC3PARAM": b"\x00\x33",
	"OPENPGPKEY": b"\x00\x3d",
	"PTR": b"\x00\x0c",
	"RRSIG": b"\x00\x2e",
	"RP": b"\x00\x11",
	"SIG": b"\x00\x18",
	"SMIMEA": b"\x00\x35",
	"SOA": b"\x00\x06",
	"SRV": b"\x00\x21",
	"SSHFP": b"\x00\x2c",
	"SVCB": b"\x00\x40",
	"TA": b"\x08\x00",
	"TKEY": b"\x00\xf9",
	"TLSA": b"\x00\x34",
	"TSIG": b"\x00\xfa",
	"TXT": b"\x00\x10",
	"URI": b"\x01\x00",
	"ZONEMD": b"\x00\x3f",

	"ANY": b"\x00\xff",
	"AXFR": b"\x00\xfc",
	"IFXR": b"\x00\xfb",
	"OPT": b"\x00\x29",
}

#See rfc 2929
classes = {
	"internet" : b'\x00\x01',
	"chaos" : b'\x00\x03',
	"hesiod" : b'\x00\x04',
	"none" : b'\x00\xfe',
	"any" : b'\x00\xff',
}

#see rfc 1035.html
opcodes = {
	"QUERY": 0, 
	"IQUERY": 1,
	"STATUS": 2,
}

#https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
options = {
	"LLQ": b"\x00\x01",
	"NSID": b"\x00\x03",
	"DAU": b"\x00\x05",
	"DHU": b"\x00\x06",
	"N3U": b"\x00\x07",
	"edns-client-subnet": b"\x00\x08",
	"EDNS EXPIRE": b"\x00\x09",
	"COOKIE": b"\x00\x0a",
	"edns-tcp-keepalive": b"\x00\x0b",
	"Padding": b"\x00\x0c",
	"CHAIN": b"\x00\x0d",
	"edns-key-tag": b"\x00\x0e",
	"Extended DNS Error": b"\x00\x0f",
	"EDNS-Client-Tag": b"\x00\x10",
	"EDNS-Server-Tag": b"\x00\x11",
	"Umbrella Ident": b'\x4f\x44',
	"DeviceID": b'\x69\x42',

}

### Tier1 creation ###

def domain2wire(text):
	parts = filter(bool, text.split("."))
	ba = bytearray()
	for p in parts:
		ba.append(len(p))
		ba += p.encode("ASCII")
	ba.append(0)

	return ba #always return byte array when possible (and perofrmant)


def wire2domain(b):
	ans = bytearray()
	index = 0
	parts = []

	c = b[0]
	while c:
		assert(c < 0b01000000) #cant do pointers on raw wire data
		index += 1
		ans += (b[index:index+c] + b".")
		index += c
		c = b[index]

	return ans.decode("ASCII")


def parts2name(parts):
	return ".".join(map(lambda x: x.decode("ASCII"), parts))


def parts2wirename(parts):
	ret = bytearray()
	for a,b in zip(map(lambda x: bytes([len(x)]), parts), parts):
		ret += a
		ret += b
	return ret


def int2word(i):
	return bytes([i // 256, i % 256])


def word2int(w):
	return w[0] * 256 + w[1]


def mkquestion(wiredomain, typ=types["A"], clas=classes["internet"]):
	ret = bytearray()
	ret += wiredomain
	ret += typ
	ret += clas
	return ret


def mkanswer(wiredomain=b'\xc0\x0c', typ=types["A"], clas=classes["internet"], ttl=b'\x00\x00\x00\x00', data=b'\x00\x00\x00\x00'):
	ret = bytearray()
	ret += wiredomain
	ret += typ
	ret += clas
	ret += ttl
	ret += int2word(len(data))
	ret += data
	return ret


def mkeflags(dnssec=True):
	return [b'\x00\x00', b'\x80\x00'][dnssec]

def mkedns(udpsize=1280, hRCODE=b'\x00', dnsssecrr=mkeflags(), data=b''): #special . OPT answer in additional records for a client request
	ret = bytearray()
	ret += b'\x00\x00\x29'
	ret += int2word(udpsize)
	ret += hRCODE
	ret += b'\x00'
	ret += [b'\x00\x00', b'\x80\x00'][dnsssecrr]
	ret += int2word(len(data))
	ret += data
	return ret


def mkflags(response=False, opcode=opcodes["QUERY"], AA=False, TC=False, RD=True, RA=False, Z=0, rcode=0):
	flagsL = 0x00
	flagsL |= (response << 7)
	flagsL |= ((opcode&0xf) << 3)
	flagsL |= (AA << 2)
	flagsL |= (TC << 1)
	flagsL |= RD

	flagsR = 0x00
	flagsR |= (RA << 7)
	flagsR |= ((Z&0x7) << 4)
	flagsR |= (rcode&0xF)

	return int2word(flagsL << 8 | flagsR)


def mkpkt(questions=[], answers=[], authorityrrs=[], additionalrrs=[], flags=mkflags(), tid=None):
	if not tid: tid = int2word(random.getrandbits(16))
	p = bytearray()
	p += tid
	p += flags
	p += int2word(len(questions))
	p += int2word(len(answers))
	p += int2word(len(authorityrrs))
	p += int2word(len(additionalrrs))
	for item in questions: p += item
	for item in answers: p += item
	for item in authorityrrs: p += item
	for item in additionalrrs: p += item

	return p

### Tier1 parsing ###

#gets wireformat name as in data (unexpanded)
def getrawwirename(data, offset=0):
	index = offset
	length = data[index]
	while length:
		if length > 0b00111111:
			return (data[index:index+2], index+2)
		index += length+1
		length = data[index]

	return (data[offset:index+1], index+1)


#data and offset to wirename, to get expanded name back
def wirenameparts(refdata, wirename):
	ptrs = set()
	parts = []

	retindex = None

	data = wirename
	index = 0
	while data[index]:
		if data[index] > 0b00111111:
			if data[index] < 0b11000000: raise Exception("Undefined / Decrecated Name Part Label")

			index = ((data[index] & 0b00111111) << 8) + data[index+1]

			if data == wirename: 
				data = refdata #were now browsing in the refdata

			if index in ptrs: raise Exception("Name Part Labels are looping")
			ptrs.add(index)
		else:
			length = data[index]
			parts.append(data[index+1:index+length+1])
			index += data[index]+1

	parts.append(b'') #the terminator is basically a 0 length segnment
	return parts


# def getwirenameparts(data, offset):
# 	ptrs = set()
# 	parts = []

# 	retindex = None
# 	index = offset
# 	while data[index]:
# 		if data[index] > 0b00111111:
# 			if data[index] < 0b11000000: raise Exception("Undefined / Decrecated Name Part Label")
# 			if retindex == None: retindex = index+2 #only store after the first p[ointer, becaus ethen the label is over
# 			index = ((data[index] & 0b00111111) << 8) + data[index+1]
# 			if index in ptrs: raise Exception("Name Part Labels are looping")
# 			ptrs.add(index)
# 		else:
# 			length = data[index]
# 			parts.append(data[index+1:index+length+1])
# 			index += data[index]+1

# 	parts.append(b'') #the terminator is basically a 0 length segnment
# 	if retindex == None: retindex = index+1 
# 	return (parts, retindex)



def getbyte(data, offset):
	return (data[offset], offset+1)

def getword(data, offset):
	return ((data[offset] << 8) | data[offset+1], offset+2)

def getdword(data, offset):
	return ((data[offset] << 24) | (data[offset+1] << 16) | (data[offset+2] << 8) | data[offset+3], offset+4)

def get(count, data, offset, **kwargs):
	e = offset+count
	return (data[offset:e], e)


def getq(data, index, namefunc=getrawwirename): #using other function than getrawwirename invalidates pointers
	wirename, index = namefunc(data, index)
	typ, index = get(2, data, index)
	clas, index = get(2, data, index)
	return ((wirename, typ, clas), index)

#beware reparsing if OPT . (EDNS is returned)
def getans(data, offset, namefunc=getrawwirename):  #using other function than getrawwirename invalidates pointers
	index = offset
	wirename, index = namefunc(data, index)
	typ, index = get(2, data, index)
	clas, index = get(2, data, index)
	ttl, index = get(4, data, index)
	datalen, index = getword(data, index)
	d, index = get(datalen, data, index)
	return ((wirename, typ, clas, ttl, d), index)


def getnum(count, getfunc, data, index, **kwargs):
	ret = []
	for _ in range(count):
		r, index = getfunc(data, index, **kwargs)
		ret.append(r)
	return (ret, index)


def getpreamble(data, offset=0):
	index = offset
	tid, index = get(2, data, index)
	flags, index = get(2, data, index)  

	nq, index = getword(data, index)
	nans, index = getword(data, index)
	nauth, index = getword(data, index)
	nadd, index = getword(data, index)

	return((tid, flags, nq, nans, nauth, nadd), index)


def getsections(data, index, preamble):
	tid, flags, nq, nans, nauth, nadd = preamble
	q, index = getnum(nq, getq, data, index)
	ans, index = getnum(nans, getans, data, index)
	auth, index = getnum(nauth, getans, data, index)
	add, index = getnum(nadd, getans, data, index)
	
	return ((q, ans, auth, add), index)


def getdns(data, offset=0):
	preamble, index = getpreamble(data)
	sections, index = getsections(data, index, preamble)
	return((preamble[:2] + sections), index)


#convert t1 parsed dns packet to parameters for the low lever mkpkt function
def dns2mkpkt(t1parsed):
	tid, flags, q, ans, auth, add = t1parsed
	
	ret = []
	ret.append( list(map(lambda x: mkquestion(*x), q)) )
	ret.append( list(map(lambda x: mkanswer(*x), ans)) )
	ret.append( list(map(lambda x: mkanswer(*x), auth)) )
	ret.append( list(map(lambda x: mkanswer(*x), add)) )
	ret.append( flags )
	ret.append( tid )
	return tuple(ret)
