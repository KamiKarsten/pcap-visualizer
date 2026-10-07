from scapy.layers.inet import TCP as ScapyTcp

from pcap_visualizer.models import TCP, TCPFlags


class TCPMapper:
	
	@staticmethod
	def map(layer) -> TCP | None:
		
		if not isinstance(layer, ScapyTcp):
			return None

		flags = TCPMapper._match_flags(layer.flags)

		return TCP(
			source_port=layer.sport,
			destination_port=layer.dport, 
			sequence_number=layer.seq, 
			acknowledgment_number=layer.ack, 
			flags=flags, 
			window=layer.window 
		)

	@staticmethod
	def _match_flags(scapyFlags) -> TCPFlags: 

		result = TCPFlags(0)
		flags = {
			"F": TCPFlags.FIN,
			"S": TCPFlags.SYN,
			"R": TCPFlags.RST,
			"P": TCPFlags.PSH,
			"A": TCPFlags.ACK,
			"U": TCPFlags.URG,
			"E": TCPFlags.ECE,
			"C": TCPFlags.CWR,
			"N": TCPFlags.NS
		}

		for scapy_flag, flag in flags.items():
			if scapy_flag in scapyFlags:
				result |= flag

		return result