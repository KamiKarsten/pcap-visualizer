from dataclasses import dataclass
from enum import IntEnum

from pcap_visualizer.models import Layer

class ARPOperation(IntEnum):
	REQUEST=1
	RESPONSE=2

@dataclass()
class ARP(Layer): 
	source_ip: str
	source_mac: str
	destination_ip: str
	destination_mac: str
	operation: ARPOperation


