from abc import ABC
from dataclasses import dataclass


@dataclass(kw_only=True)
class Layer:
	payload: "Layer | None" = None

	def __str__(self):
		if self.payload:
			return f"{self.__class__.__name__} / {self.payload}"

		return self.__class__.__name__