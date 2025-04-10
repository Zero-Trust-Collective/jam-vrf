.PHONY: develop build test docs

develop:
	uv sync
	maturin develop

build:
	uv sync
	maturin build --release

test:
	cargo test --no-default-features
	pytest -n auto

docs:
	pdoc jam_vrf -o docs