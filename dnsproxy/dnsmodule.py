from scapy.all import *
from dnspacket import DNSQueryRequest, DNSQueryResponse
from dnsdata import getdnstype
import time
import datetime
import socket
import re

class DNSServer() :
	
	class Rule() :
		""" A class containing a set of rules.
			If a given set of data matches all the rules, matches returns True.

			arg1 : re_from		Regex matching the origin ip-address of the dns-query
			arg2 : re_host 		Regex matching the hostname to be resolved
			arg3 : re_type		Regex matching the type of DNS request (NX, TXT, A...) """

			
		def __init__(self, re_from, re_host, re_type) :
			self.re_from = re.compile(re_from)
			self.re_host = re.compile(re_host)
			self.re_type = re.compile(re_type)
			
		def matches(self, q_from, q_host, q_type) :
			""" Check if the given parameters match the rule """
			if (self.re_from.search(q_from) and
				self.re_host.search(q_host) and
				self.re_type.search(q_type)) :
				return True
			return False
			
	def __init__(self) :
		self.routing = {}
	
	def listen(self, port) :
		""" Start listening for data, and pass all received
			information to the parse function """
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		s.bind(("", port))
		while True :
			data, addr = s.recvfrom(1024)
			self.parse(DNSQueryRequest(DNS(data),addr))
	
	def parse(self, request) :
		""" Iterates over the routing table invoking the approperiate functions
			It will invoke all functions assigned to a given rule and all rules matching the query """
		for rule,functions in self.routing.iteritems():
			if rule.matches(request.getIp(), request.getHost(), request.getType()):
				for func in functions:
					func(request)
			
	def dissect(self, packet, address):
		""" Dissects the packet and returns the fields 'from', 'host' and 'type' """
		dnsqr = packet.qd
		return (address[0], dnsqr.qname, DNS_TYPE_ID[dnsqr.qtype])

	def dnsrule(self, re_from=r"", re_host=r"", re_type=r""):
		""" Creates a new DNS rule
			
			arg1 : re_from		Regex to match the src ip of the packet
			arg2 : re_host		Regex to match the hostname to be resolved
			arg3 : re_type		Regex to match the DNS lookup type """
		def decorator(f):
			rule = self.Rule(re_from, re_host, re_type)
			if rule in self.routing.keys() : self.routing[rule].append(f)
			else : self.routing[rule] = [f]
			return f

		return decorator

	def log(self, fname, packet, address, note="\n"):
		""" Creates a new log entry
			
			arg1 : fname		File to append log entry to
			arg2 : packet		DNS packet to log
			arg3 : address		Sender address
			arg4 : note			Optional note to append to log
		"""
		ts = datetime.datetime.fromtimestamp(time.time()).strftime("[%Y-%m-%d %H:%M:%S]")
		with open(str(fname), "a") as f:
			f.write(ts + " <from=%s, host=%s, type=%s>\n" % self.dissect(packet, address))
			if len(note) > 0:
				f.write("%s\n\n" % note)
			else:
				f.write("\n")



