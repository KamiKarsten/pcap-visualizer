from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from ..models.packet import PacketInfo

def parse_packet(packet: Packet) -> PacketInfo:
	source = None
	destination = None
	source_port = None
	destination_port = None
	protocol = packet.name

	ip_layer = get_ip_layer(packet)
	transport_layer = get_transport_layer(packet)

	if ip_layer:
		source = ip_layer.src
		destination = ip_layer.dst

	if transport_layer:
		source_port = transport_layer.sport
		destination_port = transport_layer.dport
	
	return PacketInfo(
		source=source,
		destination=destination,
		protocol=protocol,
		source_port=source_port,
		destination_port=destination_port,
		size=len(packet)
	)

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