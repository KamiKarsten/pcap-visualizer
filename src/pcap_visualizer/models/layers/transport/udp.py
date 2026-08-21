from dataclasses import dataclass

from pcap_visualizer.models import Layer

@dataclass()
class UDP(Layer):
	source_port: int
	destination_port: int
	length: int