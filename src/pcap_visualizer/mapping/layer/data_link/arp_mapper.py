from scapy.layers.l2 import ARP as ScapyARP

from pcap_visualizer.models import ARP, ARPOperation


class ARPMapper:

	@staticmethod
	def map(layer) -> ARP | None:

		if not isinstance(layer, ScapyARP):
			return None

		try:
			arp_operation =  ARPOperation(layer.op)
		except ValueError:
			print(f"unsupported type: ARP, arp_operation, {layer.op}")
			return None
		
		return ARP(
			source_ip = layer.psrc,
			source_mac = layer.hwsrc,
			destination_ip = layer.pdst,
			destination_mac = layer.hwdst,
			operation = arp_operation
		)