# Configuration
PROFILE_DIR := tests/profiles
DATE := $(shell date +%Y%m%d)
TIME := $(shell date +%H%M%S)
PROFILE_SUBDIR := $(PROFILE_DIR)/$(DATE)
LATEST_PROFILE := $(shell find $(PROFILE_DIR) -name "*.prof" -type f -print0 | xargs -0 ls -t 2>/dev/null | head -n1)

.PHONY: build test profile docs

build:
	poetry run maturin build

develop:
	poetry run maturin develop

test:
	cargo test --no-default-features
	poetry run pytest -n auto

# Run python tests with profiling and save to latest.prof
profile:
	mkdir -p $(PROFILE_SUBDIR)
	poetry run pytest -n auto --profile --profile-svg
	@if [ -d prof ]; then \
		cp prof/combined.prof $(PROFILE_SUBDIR)/$(TIME).prof; \
		cp prof/combined.svg $(PROFILE_SUBDIR)/$(TIME).svg; \
		echo "Profile saved to $(PROFILE_SUBDIR)/$(TIME).{prof,svg}"; \
	fi

# Generate python docs
docs:
	poetry run pdoc pyvrfs -o docs