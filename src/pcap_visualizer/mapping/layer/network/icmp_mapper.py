from scapy.layers.inet import ICMP as ScapyICMP

from pcap_visualizer.models import ICMP, ICMPType

class ICMPMapper:

	@staticmethod
	def map(layer) -> ICMP | None:
	
		if not isinstance(layer, ScapyICMP):
			return None

		try:
			icmp_type =  ICMPType(layer.type)
		except ValueError:
			print(f"unsupported type: ICMP, icmp_type, {layer.type}")
			return None

		return ICMP(
			type=icmp_type,
			code=layer.code
		)