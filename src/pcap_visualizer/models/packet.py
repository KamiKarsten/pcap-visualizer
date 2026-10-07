from dataclasses import dataclass
from datetime import datetime

from .layers.layer import Layer


@dataclass
class Packet:
	layer: Layer | None
	size: int
	timestamp: datetime

	def __str__(self):
		return f"{self.layer} ({self.size} bytes)"

	def get_layer(self, layer_type: type[Layer]) -> Layer | None:

		current_layer = self.layer

		while current_layer is not None:
			if isinstance(current_layer, layer_type):
				return current_layer

			current_layer = current_layer.payload
		
		return None

	def has_layer(self, layer_type: type[Layer]) -> bool:

		current_layer = self.layer

		while current_layer is not None:
			if isinstance(current_layer, layer_type):
				return True
			current_layer = current_layer.payload

		return False