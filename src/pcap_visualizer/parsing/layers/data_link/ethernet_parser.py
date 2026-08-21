from scapy.layers.l2 import Ether as ScapyEther

from pcap_visualizer.models.layers.data_link.ethernet import Ethernet, EthernetType

class EthernetParser: 
	@staticmethod
	def parse(packet) -> Ethernet | None: 
		if not packet.haslayer(ScapyEther):
			return None
		
		ethernet = packet[ScapyEther]

		return Ethernet(
			source_mac = ethernet.src,
			destination_mac = ethernet.dst,
			ether_type = EthernetType(ethernet.type)
		)