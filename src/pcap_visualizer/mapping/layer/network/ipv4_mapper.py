from scapy.layers.inet import IP as ScapyIP

from pcap_visualizer.models import IPv4, IPv4Protocol


class IPv4Mapper:

	@staticmethod
	def map(layer) -> IPv4 | None:

		if not isinstance(layer, ScapyIP):
			return None

		try:
			ipv4_protocol = IPv4Protocol(layer.proto)
		except ValueError:
			print(f"unsupported type: IPv4, ipv4_protocol, {layer.proto}")
			return None
		
		return IPv4(
			source_ip = layer.src,
			destination_ip = layer.dst,
			ttl = layer.ttl,
			protocol = ipv4_protocol
		)