from pcap_visualizer.extractor.extractor import Extractor
from pcap_visualizer.models.information import MacAddressInfo, AddressInfo, Information
from pcap_visualizer.models.layer import ARP


class ArpExtractor(Extractor[Information]):
	def extract(self, layer: ARP) -> list[Information]:
		return [
			MacAddressInfo(
				source= layer.source_mac, 
				destination= layer.destination_mac
			), 
			AddressInfo(
				source=layer.source_ip,
				destination=layer.destination_ip
			)
		]