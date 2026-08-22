from scapy.layers.inet import ICMP as ScapyICMP

from pcap_visualizer.models import ICMP, ICMPType


class ICMPParser:
	@staticmethod
	def parse(packet) -> ICMP | None:
		if not packet.haslayer(ScapyICMP):
			return None

		icmp = packet[ScapyICMP]

		return ICMP(
			type=ICMPType(icmp.type),
			code=icmp.code
		)