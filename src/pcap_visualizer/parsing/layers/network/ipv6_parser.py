from scapy.layers.inet6 import IPv6 as ScapyIPv6

from pcap_visualizer.models import IPv6, IPv6NextHeader

class IPv6Parser:
	@staticmethod
	def parse(packet) -> IPv6 | None:
		if not packet.haslayer(ScapyIPv6):
			return None

		ipv6 = packet[ScapyIPv6]

		return IPv6(
			source_ip = ipv6.src,
			destination_ip = ipv6.dst,
			hop_limit = ipv6.hlim,
			next_header = IPv6NextHeader(ipv6.nh)
		)