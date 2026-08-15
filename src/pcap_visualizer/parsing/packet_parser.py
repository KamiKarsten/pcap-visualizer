from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NA, ICMPv6ND_NS
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet

from ..models.packet import PacketInfo
from ..models.protocols import Protocol

def parse_packet(packet: Packet) -> PacketInfo:
	source_ip = None
	source_port = None
	source_mac = None
	destination_ip = None
	destination_port = None
	destination_mac = None

	ethernet_layer = get_ethernet_layer(packet)
	if ethernet_layer:
		source_mac = ethernet_layer.src
		destination_mac = ethernet_layer.dst

	ip_layer = get_ip_layer(packet)
	if ip_layer:
		source_ip = ip_layer.src
		destination_ip = ip_layer.dst

	transport_layer = get_transport_layer(packet)
	if transport_layer:
		source_port = transport_layer.sport
		destination_port = transport_layer.dport
	
	protocol = get_protocol(packet)

	return PacketInfo(
		source_ip=source_ip,
		source_port=source_port,
		source_mac=source_mac,
		destination_ip=destination_ip,
		destination_port=destination_port,
		destination_mac=destination_mac,
		protocol=protocol,
		size=len(packet)
	)


def get_ethernet_layer(packet: Packet):
	if packet.haslayer(Ether):
		return packet[Ether]

	return None


def get_ip_layer(packet: Packet):
	if packet.haslayer(IP):
		return packet[IP]
	
	elif packet.haslayer(IPv6):
		return packet[IPv6]

	return None


def get_transport_layer(packet: Packet):
	if packet.haslayer(TCP):
		return packet[TCP]
	
	elif packet.haslayer(UDP):
		return packet[UDP]
	
	return None


def get_protocol(packet: Packet) -> Protocol:
	if packet.haslayer(TCP):
		return Protocol.TCP
	
	if packet.haslayer(UDP):
		return Protocol.UDP
	
	if packet.haslayer(ICMP):
		return Protocol.ICMP
	
	if packet.haslayer(ICMPv6ND_NS) or packet.haslayer(ICMPv6ND_NA):
		return Protocol.ICMPV6
	
	if packet.haslayer(ARP):
		return Protocol.ARP

	return Protocol.ETHERNET