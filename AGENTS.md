# AGENTS.md

Agent instructions for the PCAP Visualizer repository.

## What this project is
Python (>=3.12, scapy) tool: PCAP -> scapy packets -> custom protocol-layer models -> extracted, standardized information (MACs, IPs, ports, protocols).
The visualization itself is not implemented yet - `src/pcap_visualizer/main.py` is a CLI harness that prints extracted info per packet (see README "Ideas").

## Layout
- `src/pcap_visualizer/` - the package: `main.py` (entrypoint), `ingestion/` (PCAP reading), `mapping/` (scapy layers -> models), `models/` (custom models), `extractor/` (models -> information).
- `src/tests/` - pytest suite, mirrors the package tree. Note: tests live under `src/`, not the repo root; setuptools excludes them from the wheel.
- `captures/` - sample PCAPs; gitignored and NOT tracked. A fresh clone has no `captures/` directory.

## Commands (run from the repo root)
```bash
# setup (first time)
python -m venv .venv
source .venv/bin/activate
python -m pip install -e . --group dev    # --group needs pip >= 25.1
# older pip: python -m pip install -e . && python -m pip install pytest coverage

# run the app (hardcodes captures/example.pcap - see Gotchas)
python -m pcap_visualizer.main

# tests
pytest                                                                 # full suite
pytest src/tests/mapping/layer/data_link/test_arp_mapper.py            # one file
pytest src/tests/mapping/layer/data_link/test_arp_mapper.py::test_map_returns_arp_object_when_packet_has_arp_layer  # one test
coverage run -m pytest && coverage report                              # coverage is preconfigured for src/pcap_visualizer
```

## Gotchas
- Indentation is TABS across all `.py` files in the repo (deliberate - commit cb1bddf). Do not reformat to spaces or mix styles.
- `pip install --group dev` (the README setup) requires pip >= 25.1; on older pip, install the dev deps manually (see above).
- Tests require the editable install first: they import `pcap_visualizer` and there is no conftest/sys.path hack.
- `main.py` reads `captures/example.pcap` via a hardcoded relative path: it only works from the repo root, and that file is not in git - on a fresh clone, point it at your own capture or edit the filename in `main.py`.
- `read_pcap` (src/pcap_visualizer/ingestion/pcap_reader.py) is a generator: it yields scapy packets lazily.
- No linter, formatter, typechecker, or CI is configured in this repo - do not assume formatting passes or CI checks.

## Pipeline and where new protocol layers register
Flow: `read_pcap` -> scapy packets -> `PacketMapper.map` (chained `Layer` models via `.payload`) -> `InformationExtractor.extract` -> `list[Information]`.

Adding a protocol layer touches every stage (category is one of `data_link`, `network`, `transport`):
1. Model: `models/layer/<category>/<layer>.py` (a `@dataclass()` subclass of `Layer`; the base `Layer` is `@dataclass(kw_only=True)`), re-exported in `models/layer/<category>/__init__.py`, `models/layer/__init__.py` and `models/__init__.py` (all keep `__all__`).
2. Mapper: `mapping/layer/<category>/<layer>_mapper.py` (a class with `@staticmethod map(layer) -> <Model> | None`), re-exported in `mapping/layer/<category>/__init__.py`, `mapping/layer/__init__.py` and `mapping/__init__.py`, and added to the `PacketMapper.mappers` list in `mapping/packet_mapper.py` (first non-None match wins).
3. Extractor: `extractor/layer/<category>/<layer>_extractor.py` (subclass of `Extractor[T]`), re-exported in `extractor/layer/<category>/__init__.py` and registered in the `EXTRACTORS` dict in `extractor/information_extractor.py`.
4. Tests: mirror the new files under `src/tests/`.

Not every mapped layer has an extractor: ICMP and ICMPv6 are mapped but not registered in `EXTRACTORS` (they surface only as `ProtocolInfo` when deepest). Don't assume mapper/extractor symmetry.

## Workflow
Feature branches merged to `main` via PR (see git history); no CI gates.
