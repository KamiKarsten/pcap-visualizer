from typing import Any

from pcap_visualizer.models import Packet, Layer, Ethernet, ARP, IPv4, IPv6, TCP, UDP 
from pcap_visualizer.models.information import Information, ProtocolInfo

from pcap_visualizer.extractor.extractor import Extractor
from pcap_visualizer.extractor import EtherExtractor, ArpExtractor, Ipv4Extractor, Ipv6Extractor, TCPExtractor, UDPExtractor


EXTRACTORS: dict[type[Layer], Extractor[Any]] = {
		Ethernet: EtherExtractor(),
		ARP: ArpExtractor(),
		IPv4: Ipv4Extractor(),
		IPv6: Ipv6Extractor(),
		TCP: TCPExtractor(),
		UDP: UDPExtractor(),
}


class InformationExtractor:
	@staticmethod
	def extract(packet: Packet) -> list[Information]:
		information: list[Information] = []
		layer: Layer | None = packet.layer
		highest_layer: Layer | None = None

		while layer is not None:
			highest_layer = layer
			extractor = EXTRACTORS.get(type(layer))

			if extractor is not None:
				information.extend(extractor.extract(layer))

			layer = layer.payload

		if highest_layer is not None:
			information.append(
				ProtocolInfo(
					protocol=type(highest_layer).__name__
				)
			)

		return information