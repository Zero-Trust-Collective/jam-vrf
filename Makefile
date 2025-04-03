.PHONY: test docs

test:
	cargo test --no-default-features
	uv sync
	pytest -n auto

docs:
	pdoc pyvrfs -o docs -d markdown