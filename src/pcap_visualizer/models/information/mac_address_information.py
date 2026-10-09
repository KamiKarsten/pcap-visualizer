from dataclasses import dataclass

from pcap_visualizer.models.information.information import Information

@dataclass()
class MacAddressInfo(Information):
	source: str
	destination: str