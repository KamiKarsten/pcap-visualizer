from scapy.layers.inet import TCP as ScapyTcp

from pcap_visualizer.models import TCP, TCPFlags


class TCPMapper:

	@staticmethod
	def map(layer) -> TCP | None:

		if not isinstance(layer, ScapyTcp):
			return None

		flags = TCPFlags(int(layer.flags) & 0x1FF)

		return TCP(
			source_port=layer.sport,
			destination_port=layer.dport, 
			sequence_number=layer.seq, 
			acknowledgment_number=layer.ack, 
			flags=flags, 
			window=layer.window 
		)