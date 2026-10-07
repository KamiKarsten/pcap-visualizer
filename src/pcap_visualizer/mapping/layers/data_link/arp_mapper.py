from scapy.layers.l2 import ARP as ScapyARP

from pcap_visualizer.models import ARP, ARPOperation


class ARPMapper:

	@staticmethod
	def map(layer) -> ARP | None:

		if not isinstance(layer, ScapyARP):
			return None

		return ARP(
			source_ip = layer.psrc,
			source_mac = layer.hwsrc,
			destination_ip = layer.pdst,
			destination_mac = layer.hwdst,
			operation = ARPOperation(layer.op)
		)