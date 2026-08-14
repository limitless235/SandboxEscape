PYTHON ?= python3
COMPOSE ?= docker compose
PYTEST ?= $(PYTHON) -m pytest

.PHONY: test test-unit test-isolation scorecard agent-benign agent-adversarial \
	up down locked-up leaky-up chained-up build

test: test-unit

test-unit:
	$(PYTEST) -q -m "not integration"

test-isolation:
	$(PYTEST) -q -m integration

scorecard:
	$(PYTHON) -m agent.scorecard

agent-benign:
	$(PYTHON) -m agent.main --mode benign --workspace sandbox/workspace

agent-benign-docker:
	SANDBOX_URL=exec://sandbox $(PYTHON) -m agent.main --mode benign --workspace sandbox/workspace

agent-adversarial:
	$(PYTHON) -m agent.main --mode adversarial --workspace sandbox/workspace

build:
	$(COMPOSE) build

up locked-up:
	$(COMPOSE) -f compose.yaml up --build -d

leaky-up:
	$(COMPOSE) -f compose.yaml -f compose.leaky.yaml up --build -d

chained-up:
	$(COMPOSE) -f compose.yaml -f compose.chained.yaml up --build -d

down:
	$(COMPOSE) down -v
