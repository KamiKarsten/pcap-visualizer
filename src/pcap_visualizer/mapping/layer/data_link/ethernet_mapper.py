from scapy.layers.l2 import Ether as ScapyEther

from pcap_visualizer.models import Ethernet, EthernetType


class EthernetMapper:

	@staticmethod
	def map(layer) -> Ethernet | None: 

		if not isinstance(layer, ScapyEther):
			return None

		try:
			ether_type = EthernetType(layer.type)
		except ValueError:
			print(f"unsupported type: Ethernet, ether_type, {layer.type}")
			return None
		
		return Ethernet(
			source_mac = layer.src,
			destination_mac = layer.dst,
			ether_type = ether_type
		)