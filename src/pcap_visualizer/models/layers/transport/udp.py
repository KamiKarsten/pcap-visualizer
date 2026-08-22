from dataclasses import dataclass

from ..layer import Layer


@dataclass()
class UDP(Layer):
	source_port: int
	destination_port: int
	length: int