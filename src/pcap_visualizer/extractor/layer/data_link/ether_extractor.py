from pcap_visualizer.extractor.extractor import Extractor
from pcap_visualizer.models.information import MacAddressInfo
from pcap_visualizer.models.layer import Ethernet


class EtherExtractor(Extractor[MacAddressInfo]):
	def extract(self, layer: Ethernet) -> list[MacAddressInfo]:
		return [
			MacAddressInfo(
				source= layer.source_mac, 
				destination= layer.destination_mac
			)
		]