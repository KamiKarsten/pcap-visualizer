from dataclasses import dataclass
from datetime import datetime

from pcap_visualizer.models.information.information import Information


@dataclass()
class PacketInfo(Information):
	size: int
	timestamp: datetime