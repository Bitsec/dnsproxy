from scapy.all import *
from random import randint
from dnsdata import getdnstype
import socket
class DNSQueryRequest() :
	def __init__(self, packet, address) :
		self.packet = packet
		self.address = address

	def getHost(self) :
		""" Returns name of requested host """
		return self.packet.qd.qname
	
	def getType(self) :
		""" Returns type of request in string format """
		return getdnstype(self.packet.qd.qtype)

	def getTypeId(self) :
		""" Returns the request type id """
		return self.packet.qd.qtype
	
	def getPort(self) :
		""" Returns origin port number """
		return self.address[1]

	def getIp(self) :
		""" Returns origin ip address """
		return self.address[0]
	

class DNSQueryResponse() :
	def __init__(self) :
		pass

	def doDNSResponse(self, request, myip, data) :
		""" Sends a response to a given DNS Query
			
			arg1 : request		The request object to respond to
			arg2 : myip			The src ip of the response
			arg3 : data			The data to be returned """
		pkt = (IP(src=source, dst=request.getIp())/
				  UDP(dport=request.getPort())/
				  DNS(id=request.packet.id, qr=1, qdcount=1, ancount=1, nscount=0, arcount=0,
					  qd=request.packet.qd, 
					  an=DNSRR(
							ttl=100, rclass=request.packet.qd.qclass,
							rrname=request.getHost(),
							type=request.getTypeId(),
							rdata=data)))
		send(pkt)
	
	def passThroughDNS(self, request, srcip, srcport, dnsserver) :
		""" Forwards the packet to a given dns server and returns
			a returns the response to the source
			
			arg1 : request		The request object to respond to
			arg2 : srcip		The src ip of the response
			arg3 : srcport 		The port of the reponse
			arg3 : dnsserver	The ip of the dns-server to forward request to """

		# Randomly chosen ports may cause problems on busy machines!
		source_port = randint(4096, 65534)

		# Create and send request to real server
		pkt = (IP(src=myip, dst=dnsserver)/
				UDP(dport=53,sport=source_port)/
				DNS(id=request.packet.id, qr=0, rd=1,
					qdcount=1, qd=request.packet.qd))

		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.bind(('', source_port))
		send(pkt)

		# Receive, decode and forward server response
		data, addr = s.recvfrom(1024)
		pkt = DNS(data)
		send(IP(src=myip, dst=request.getIp())/
			 UDP(sport=srcport, dport=request.getPort())/pkt)
