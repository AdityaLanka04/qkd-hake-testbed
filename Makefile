PYTHON ?= python3
VENV := .venv
BIN := $(VENV)/bin

.PHONY: setup test server demo clean transfer-init transfer-receive transfer-verify

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

transfer-init:
	$(BIN)/python -m qkd_hake.cli transfer init

transfer-receive:
	$(BIN)/python -m qkd_hake.cli transfer receive

transfer-verify:
	$(BIN)/python -m qkd_hake.cli transfer verify-demo

clean:
	find src tests -type d -name __pycache__ -prune -exec rm -r {} +
	rm -rf .pytest_cache build dist
