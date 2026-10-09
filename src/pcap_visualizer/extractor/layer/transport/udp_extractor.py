from pcap_visualizer.extractor.extractor import Extractor
from pcap_visualizer.models.information import PortInfo
from pcap_visualizer.models.layer import UDP


class UDPExtractor(Extractor[PortInfo]):
	def extract(self, layer: UDP) -> list[PortInfo]:
		return [
			PortInfo(
				source= layer.source_port,
				destination= layer.destination_port
			)
		]