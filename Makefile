PYTHON ?= python3
VENV := .venv
BIN := $(VENV)/bin

.PHONY: setup test server demo clean

setup:
	$(PYTHON) -m venv $(VENV)
	$(BIN)/python -m pip install --upgrade pip
	$(BIN)/pip install -e ".[dev]"

test:
	$(BIN)/pytest -q

server:
	$(BIN)/python -m qkd_hake.cli server

demo:
	$(BIN)/python -m qkd_hake.cli demo

clean:
	find src tests -type d -name __pycache__ -prune -exec rm -r {} +
	rm -rf .pytest_cache build dist
