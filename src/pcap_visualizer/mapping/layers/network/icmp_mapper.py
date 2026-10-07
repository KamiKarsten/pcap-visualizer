from scapy.layers.inet import ICMP as ScapyICMP

from pcap_visualizer.models import ICMP, ICMPType


class ICMPMapper:

	@staticmethod
	def map(layer) -> ICMP | None:
	
		if not isinstance(layer, ScapyICMP):
			return None

		return ICMP(
			type=ICMPType(layer.type),
			code=layer.code
		)