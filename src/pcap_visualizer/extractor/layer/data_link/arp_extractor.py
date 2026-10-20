from pcap_visualizer.extractor.extractor import Extractor
from pcap_visualizer.models.information import AddressInfo, Information, MacAddressInfo
from pcap_visualizer.models.layer import ARP


class ArpExtractor(Extractor[Information]):
	def extract(self, layer: ARP) -> list[Information]:
		return [
			MacAddressInfo(
				source_mac = layer.source_mac, 
				destination_mac = layer.destination_mac
			), 
			AddressInfo(
				source_ip = layer.source_ip,
				destination_ip = layer.destination_ip
			)
		]