from scapy.layers.inet import TCP as ScapyTcp

from pcap_visualizer.models import TCP, TCPFlags

class TCPParser:
	@staticmethod
	def parse(packet) -> TCP | None:
		if not packet.haslayer(ScapyTcp):
			return None


		tcp = packet[ScapyTcp]
		flags = TCPParser.matchFlags(tcp.flags)

		return TCP(
			source_port=tcp.sport,
			destination_port=tcp.dport, 
			sequence_number=tcp.seq, 
			acknowledgment_number=tcp.ack, 
			flags=flags, 
			window=tcp.window 
		)

	@staticmethod
	def matchFlags(scapyFlags) -> TCPFlags: 

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