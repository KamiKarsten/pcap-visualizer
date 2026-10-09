from pcap_visualizer.models.layer import Layer

def test_str_returns_layer_name_without_payload():
	layer = Layer()

	assert str(layer) == "Layer"


def test_str_includes_payload_chain():
	payload = Layer()
	layer = Layer(payload=payload)

	assert str(layer) == "Layer / Layer"