from dataclasses import dataclass

from .layers.layer import Layer

@dataclass
class Packet:
	layers: list[Layer]
	size: int

	def get_layer(self, layer_type: type[Layer]) -> Layer | None:
		for layer in self.layers:
			if isinstance(layer, layer_type):
				return layer
		return None

	def has_layer(self, layer_type: type[Layer]) -> bool:
		return any(isinstance(layer, layer_type) for layer in self.layers)