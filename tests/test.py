from context import dnsproxy
#from dnsproxy import DNSServer

dns = DNSServer()
@dns.dnsrule(re_from="^10[.]8[.]32[.]34")
def void1(request) :
	print("Received packet from myself1")

@dns.dnsrule(re_from="^10[.]8[.]32[.]34$")
def void2(request) :
	print("Received packet from myself2")

@dns.dnsrule(re_host="^google[.]com[.]$")
def void3(request) :
	print("Someone is asking for google")

@dns.dnsrule(re_host="zeta-two\.com\.$", re_type="^CNAME$")
def void4(request) :
	print("CNAME Request for zeta-two.com")
	DNSQueryResponse().passThroughDNS(request, "10.8.32.34", "8.8.8.8")

@dns.dnsrule(re_host="bitsec\.se", re_type="^A$")
def void5(request) :
	print("Lookup of type A for bitsec.se detected")
	DNSQueryResponse().doDNSResponse(request, "10.8.32.34", "13.37.13.37")
	
dns.listen()