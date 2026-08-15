from enum import Enum

class Protocol(Enum):
	ETHERNET="Ethernet"
	TCP = "TCP"
	UDP = "UDP"
	ICMP = "ICMP"
	ICMPV6 = "ICMPv6"
	ARP = "ARP"
	OTHER = "Other"