from scapy.layers.l2 import Ether as ScapyEther
from scapy.layers.l2 import ARP as ScapyARP

from scapy.layers.inet import IP as ScapyIP
from scapy.layers.inet6 import IPv6 as ScapyIPv6
from scapy.layers.inet import TCP as ScapyTCP
from scapy.layers.inet import UDP as ScapyUDP
from scapy.layers.inet import ICMP as ScapyICMP
from scapy.layers.inet6 import ICMPv6EchoRequest as ScapyICMPv6EchoRequest
from scapy.layers.dns import DNS as ScapyDNS
from scapy.layers.dns import DNSQR as ScapyDNSQR


from pcap_visualizer.models import Packet, Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, ICMPv6Type
from pcap_visualizer.mapping import PacketMapper


def test_map_ipv4_tcp_packet():
	packet = (
		ScapyEther() 
		/ ScapyIP(src="192.168.0.10", dst="192.168.0.20")
		/ ScapyTCP(sport=12345, dport=443)
	)

	result = PacketMapper.map(packet)

	assert isinstance(result, Packet)
	assert result.size == len(packet)

	assert result.has_layer(Ethernet)

	ipv4_layer = result.get_layer(IPv4)
	tcp_layer = result.get_layer(TCP)

	assert ipv4_layer is not None
	assert tcp_layer is not None

	assert result.layer.payload is ipv4_layer

	assert ipv4_layer.source_ip == "192.168.0.10"
	assert ipv4_layer.destination_ip == "192.168.0.20"
	assert ipv4_layer.payload is tcp_layer
	
	assert tcp_layer.source_port == 12345
	assert tcp_layer.destination_port == 443
	assert tcp_layer.payload is None

def test_map_ipv4_udp_packet():
	packet = (
		ScapyEther() 
		/ ScapyIP(src="10.0.0.1", dst="10.0.0.2")
		/ ScapyUDP(sport=54321, dport=53)
	)

	result = PacketMapper.map(packet)

	assert isinstance(result, Packet)
	assert result.size == len(packet)

	assert result.has_layer(Ethernet)
	assert result.has_layer(IPv4)
	assert result.has_layer(UDP)

	ipv4_layer = result.get_layer(IPv4)
	udp_layer = result.get_layer(UDP)

	assert ipv4_layer is not None
	assert udp_layer is not None

	assert ipv4_layer.source_ip == "10.0.0.1"
	assert ipv4_layer.destination_ip == "10.0.0.2"
		
	assert udp_layer.source_port == 54321
	assert udp_layer.destination_port == 53

def test_map_ipv4_icmp_packet():
	packet = (
		ScapyEther() 
		/ ScapyIP(src="172.16.0.1", dst="172.16.0.2")
		/ ScapyICMP(type=8, code=0)
	)

	result = PacketMapper.map(packet)
	
	assert isinstance(result, Packet)
	assert result.size == len(packet)

	assert result.has_layer(Ethernet)
	assert result.has_layer(IPv4)
	assert result.has_layer(ICMP)

	ipv4_layer = result.get_layer(IPv4)
	icmp_layer = result.get_layer(ICMP)

	assert ipv4_layer is not None
	assert icmp_layer is not None

	assert ipv4_layer.source_ip == "172.16.0.1"
	assert ipv4_layer.destination_ip == "172.16.0.2"
		
	assert icmp_layer.type == 8
	assert icmp_layer.code == 0

def test_map_ipv6_tcp_packet():
	packet = (
			ScapyEther() 
			/ ScapyIPv6(src="2001:db8::1", dst="2001:db8::2")
			/ ScapyTCP(sport=12345, dport=22)
		)
	
	result = PacketMapper.map(packet)
	
	assert isinstance(result, Packet)
	assert result.size == len(packet)

	assert result.has_layer(Ethernet)
	assert result.has_layer(IPv6)
	assert result.has_layer(TCP)

	ipv6_layer = result.get_layer(IPv6)
	tcp_layer = result.get_layer(TCP)

	assert ipv6_layer is not None
	assert tcp_layer is not None
	

	assert ipv6_layer.source_ip == "2001:db8::1"
	assert ipv6_layer.destination_ip == "2001:db8::2"
		
	assert tcp_layer.source_port == 12345
	assert tcp_layer.destination_port == 22

def test_map_ipv6_udp_packet():
	packet = (
			ScapyEther() 
			/ ScapyIPv6(src="2001:db8::2", dst="2001:db8::3")
			/ ScapyUDP(sport=54321, dport=53)
		)
	
	result = PacketMapper.map(packet)
	
	assert isinstance(result, Packet)
	assert result.size == len(packet)

	assert result.has_layer(Ethernet)
	assert result.has_layer(IPv6)
	assert result.has_layer(UDP)

	ipv6_layer = result.get_layer(IPv6)
	udp_layer = result.get_layer(UDP)

	assert ipv6_layer is not None
	assert udp_layer is not None

	assert ipv6_layer.source_ip == "2001:db8::2"
	assert ipv6_layer.destination_ip == "2001:db8::3"
		
	assert udp_layer.source_port == 54321
	assert udp_layer.destination_port == 53

def test_map_ipv6_icmpv6_packet():
	packet = (
			ScapyEther() 
			/ ScapyIPv6(src="2001:db8::2", dst="2001:db8::3")
			/ ScapyICMPv6EchoRequest()
		)
	
	result = PacketMapper.map(packet)
	
	assert isinstance(result, Packet)
	assert result.size == len(packet)

	assert result.has_layer(Ethernet)
	assert result.has_layer(IPv6)
	assert result.has_layer(ICMPv6)

	ipv6_layer = result.get_layer(IPv6)
	icmpv6_layer = result.get_layer(ICMPv6)

	assert ipv6_layer is not None
	assert icmpv6_layer is not None

	assert ipv6_layer.source_ip == "2001:db8::2"
	assert ipv6_layer.destination_ip == "2001:db8::3"
		
	assert icmpv6_layer.type == ICMPv6Type.ECHO_REQUEST

def test_map_ethernet_arp_packet():
	packet = (
		ScapyEther()
		/ ScapyARP(
			psrc="192.168.0.1",
			pdst="192.168.0.2",
		)
	)

	result = PacketMapper.map(packet)

	assert isinstance(result, Packet)
	assert result.size == len(packet)

	assert result.has_layer(Ethernet)
	assert result.has_layer(ARP)

	ethernet_layer = result.get_layer(Ethernet)
	arp_layer = result.get_layer(ARP)

	assert ethernet_layer is not None
	assert arp_layer is not None

	assert arp_layer.source_ip == "192.168.0.1"
	assert arp_layer.destination_ip == "192.168.0.2"

def test_map_packet_with_unsupported_layer():
	packet = (
		ScapyEther()
		/ ScapyIP(src="192.168.0.10", dst="8.8.8.8")
		/ ScapyUDP(sport=12345, dport=53)
		/ ScapyDNS(rd=1, qd=ScapyDNSQR(qname="example.com"))
	)
	
	result = PacketMapper.map(packet)

	assert isinstance(result, Packet)
	assert result.size == len(packet)

	assert result.has_layer(Ethernet)
	assert result.has_layer(IPv4)
	assert result.has_layer(UDP)