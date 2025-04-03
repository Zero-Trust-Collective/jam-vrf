.PHONY: test docs

test:
	cargo test --no-default-features
	uv sync
	pytest -n auto

docs:
	pdoc pyvrf -o docs -d markdown