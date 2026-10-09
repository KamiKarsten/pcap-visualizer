from pcap_visualizer.extractor.extractor import Extractor
from pcap_visualizer.models.information import AddressInfo
from pcap_visualizer.models.layer import IPv4


class Ipv4Extractor(Extractor[AddressInfo]):
	def extract(self, layer: IPv4) -> list[AddressInfo]:
		return [
			AddressInfo(
				source = layer.source_ip,
				destination=layer.destination_ip
			)
		]