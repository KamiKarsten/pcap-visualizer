from pcap_visualizer.models import Packet

from .layers import ( 
	ARPParser,
	EthernetParser,
	IPv4Parser,
	IPv6Parser,
	ICMPParser,
	ICMPv6Parser,
	TCPParser,
	UDPParser
)

class PacketParser:
	parsers = [
		EthernetParser,
		ARPParser,
		IPv4Parser,
		IPv6Parser,
		ICMPParser,
		ICMPv6Parser,
		TCPParser,
		UDPParser
	]

	@staticmethod
	def parse(packet) -> Packet:
		layers = []

		for parser in PacketParser.parsers:
			layer = parser.parse(packet)

			if layer is not None:
				layers.append(layer)

		return Packet(
			layers=layers,
			size=len(packet)
		)