from scapy.layers.l2 import ARP as ScapyARP

from pcap_visualizer.models import ARP, ARPOperation


class ARPParser:
	@staticmethod
	def parse(packet) -> ARP | None:
		if not packet.haslayer(ScapyARP):
			return None

		arp = packet[ScapyARP]

		return ARP(
			source_ip = arp.psrc,
			source_mac = arp.hwsrc,
			destination_ip = arp.pdst,
			destination_mac = arp.hwdst,
			operation = ARPOperation(arp.op)
		)