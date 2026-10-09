from typing import Any

from pcap_visualizer.extractor.extractor import Extractor
from pcap_visualizer.extractor.layer import (
	ArpExtractor,
	EtherExtractor,
	Ipv4Extractor,
	Ipv6Extractor,
	TCPExtractor,
	UDPExtractor,
)
from pcap_visualizer.models.information import Information, PacketInfo, ProtocolInfo
from pcap_visualizer.models.layer import ARP, TCP, UDP, Ethernet, IPv4, IPv6, Layer
from pcap_visualizer.models.packet import Packet

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
		information: list[Information] = [
			PacketInfo(
				size = packet.size,
				timestamp = packet.timestamp,
			)
		]

		layer: Layer | None = packet.layer
		deepest_layer: Layer | None = None

		while layer is not None:
			deepest_layer = layer
			extractor = EXTRACTORS.get(type(layer))

			if extractor is not None:
				information.extend(extractor.extract(layer))

			layer = layer.payload

		if deepest_layer is not None:
			information.append(
				ProtocolInfo(
					protocol=type(deepest_layer).__name__
				)
			)

		return information