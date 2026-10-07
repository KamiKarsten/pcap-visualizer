from typing import ClassVar

from scapy.packet import NoPayload

from pcap_visualizer.models import Layer, Packet

from .layers import (
	ARPMapper,
	EthernetMapper,
	ICMPMapper,
	ICMPv6Mapper,
	IPv4Mapper,
	IPv6Mapper,
	TCPMapper,
	UDPMapper,
)


class PacketMapper:
	mappers: ClassVar[list[type]] = [
		EthernetMapper,
		ARPMapper,
		IPv4Mapper,
		IPv6Mapper,
		ICMPMapper,
		ICMPv6Mapper,
		TCPMapper,
		UDPMapper
	]

	@staticmethod
	def map(packet) -> Packet:
		root_layer: Layer | None = None 
		last_layer : Layer | None = None 
		scapy_layer = packet

		while not isinstance(scapy_layer, NoPayload):
			mapped_layer = PacketMapper._map_layer(scapy_layer)

			if mapped_layer is not None:
				if root_layer is None:
					root_layer = mapped_layer
				else:
					last_layer.payload = mapped_layer

				last_layer = mapped_layer

			scapy_layer = scapy_layer.payload

		return Packet(
			layer=root_layer,
			size=len(packet),
			timestamp=packet.time
		)

	@staticmethod
	def _map_layer(scapy_layer) -> Layer | None:
		for mapper in PacketMapper.mappers:
			mapped_layer = mapper.map(scapy_layer)

			if mapped_layer is not None:
				return mapped_layer

		return None