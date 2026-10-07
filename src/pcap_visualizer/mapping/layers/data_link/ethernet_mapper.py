from scapy.layers.l2 import Ether as ScapyEther

from pcap_visualizer.models import Ethernet, EthernetType


class EthernetMapper:

	@staticmethod
	def map(layer) -> Ethernet | None: 

		if not isinstance(layer, ScapyEther):
			return None
		
		return Ethernet(
			source_mac = layer.src,
			destination_mac = layer.dst,
			ether_type = EthernetType(layer.type)
		)