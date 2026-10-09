from dataclasses import dataclass

from pcap_visualizer.models.information.information import Information


@dataclass()
class PortInfo(Information):
	source: int
	destination: int