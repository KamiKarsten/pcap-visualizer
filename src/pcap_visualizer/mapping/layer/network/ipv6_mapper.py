from scapy.layers.inet6 import IPv6 as ScapyIPv6

from pcap_visualizer.models import IPv6, IPv6NextHeader


class IPv6Mapper:

	@staticmethod
	def map(layer) -> IPv6 | None:
		
		if not isinstance(layer, ScapyIPv6):
			return None

		try: 
			ipv6_next_header = IPv6NextHeader(layer.nh)
		except ValueError:
			print(f"unsupported type: IPv6, ipv6_next_header, {layer.nh}")
			return None
		
		return IPv6(
			source_ip = layer.src,
			destination_ip = layer.dst,
			hop_limit = layer.hlim,
			next_header = ipv6_next_header
		)