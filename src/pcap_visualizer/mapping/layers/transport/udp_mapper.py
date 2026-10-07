from scapy.layers.inet import UDP as ScapyUdp

from pcap_visualizer.models import UDP


class UDPMapper:
	
	@staticmethod
	def map(layer) -> UDP | None:
		if not isinstance(layer, ScapyUdp):
			return None

		return UDP(
			source_port=layer.sport,
			destination_port=layer.dport, 
			length= layer.len
		)