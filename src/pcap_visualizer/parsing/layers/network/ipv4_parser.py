from scapy.layers.inet import IP as ScapyIP

from pcap_visualizer.models import IPv4, IPv4Protocol

class IPv4Parser:
	@staticmethod
	def parse(packet) -> IPv4 | None:
		if not packet.haslayer(ScapyIP):
			return None

		ip = packet[ScapyIP]

		return IPv4(
			source_ip = ip.src,
			destination_ip= ip.dst,
			ttl = ip.ttl,
			protocol= IPv4Protocol(ip.proto)
		)