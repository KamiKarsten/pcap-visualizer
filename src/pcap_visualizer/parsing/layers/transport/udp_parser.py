from scapy.layers.inet import UDP as ScapyUdp

from pcap_visualizer.models import UDP


class UDPParser:
	@staticmethod
	def parse(packet) -> UDP | None:
		if not packet.haslayer(ScapyUdp):
			return None

		udp = packet[ScapyUdp]

		return UDP(
			source_port=udp.sport,
			destination_port=udp.dport, 
			length= udp.len
		)