.PHONY: build test docs

build:
	uv sync
	maturin develop
	maturin build

test:
	cargo test --no-default-features
	pytest -n auto

docs:
	pdoc pyvrf -o docs