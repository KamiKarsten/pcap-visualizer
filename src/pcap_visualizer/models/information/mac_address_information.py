from dataclasses import dataclass

from pcap_visualizer.models.information.information import Information


@dataclass()
class MacAddressInfo(Information):
	source_mac: str
	destination_mac: str