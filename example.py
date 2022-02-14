#!/usr/bin/env pypy3
from rawdns.wirefmt import *
from rawdns.conn import *

pkt = mkpkt([mkquestion( domain2wire("example.com") )])#basically dig A example.com
cloudflare = map4to6("1.1.1.1") #conn always uses IPV6 sockets, which can also perform IPv4

d,_ = getdns(tcprequest(pkt, cloudflare))
print(d)
d,_ = getdns(udprequest(pkt, cloudflare))
print(d)
d,_ = getdns(tlsrequest(pkt, cloudflare, verify=True))
print(d)
d,_ = getdns(dohrequest(pkt, cloudflare, verify=True))
print(d)