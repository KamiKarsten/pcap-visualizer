from pcap_visualizer.extractor.extractor import Extractor
from pcap_visualizer.models.information import AddressInfo
from pcap_visualizer.models.layer import IPv6


class Ipv6Extractor(Extractor[AddressInfo]):
	def extract(self, layer: IPv6) -> list[AddressInfo]:
		return [
			AddressInfo(
				source=layer.source_ip,
				destination=layer.destination_ip
			)
		]