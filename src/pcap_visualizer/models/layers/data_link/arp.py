from dataclasses import dataclass
from enum import IntEnum

from ..layer import Layer


class ARPOperation(IntEnum):
	REQUEST=1
	REPLY=2

@dataclass()
class ARP(Layer): 
	source_ip: str
	source_mac: str
	destination_ip: str
	destination_mac: str
	operation: ARPOperation


