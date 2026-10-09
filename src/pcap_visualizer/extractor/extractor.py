from abc import ABC, abstractmethod
from typing import Generic, TypeVar

from pcap_visualizer.models.information import Information
from pcap_visualizer.models.layer import Layer


T = TypeVar("T", bound=Information)

class Extractor(ABC, Generic[T]):
	@abstractmethod
	def extract(self, layer: Layer) -> list[T] | None:
		raise NotImplementedError # pragma: no cover