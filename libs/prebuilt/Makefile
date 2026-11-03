.PHONY: all format lint type test test-fast test_watch integration_tests spell_check spell_fix benchmark profile security-verify security-verify-fast security-verify-complete security-verify-regressions security-verify-permutations security-verify-lean

# Default target executed when no arguments are given to make.
all: help

# Source-only verification and repair queue. Missing proof evidence fails the
# default command; the older complete target remains an equivalent alias.
SECURITY_REPORT ?= security-verification-report.json
# Route-scoped acceptance recomputes every manifest check, including a fresh
# Lean audit written under SECURITY_EVIDENCE_DIR (a new directory per run).
SECURITY_EVIDENCE_DIR ?= security-route-evidence
security-verify:
	uv run python ../../proofs/slp-cedar/check.py
	uv run python -m langgraph.prebuilt.security.developer_verification --output "$(SECURITY_REPORT)" --evidence-dir "$(SECURITY_EVIDENCE_DIR)"

# Same gate without the Lean audit; the lean-audit check then fails closed.
security-verify-fast:
	uv run python -m langgraph.prebuilt.security.developer_verification --output "$(SECURITY_REPORT)" --no-lean-audit

security-verify-complete:
	uv run python -m langgraph.prebuilt.security.developer_verification --require-complete --output "$(SECURITY_REPORT)"

# CI implementation gate. This keeps verifier-owned proof gaps visible without
# misrepresenting them as discharged system-completeness obligations.
security-verify-regressions:
	uv run python -m langgraph.prebuilt.security.developer_verification --require-regression-clean --output "$(SECURITY_REPORT)"

# Finite regression evidence, separate from the system-proof acceptance gate.
SECURITY_PERMUTATION_REPORT ?= security-permutation-report.json
security-verify-permutations:
	uv run python -m langgraph.prebuilt.security.permutation_verification --output "$(SECURITY_PERMUTATION_REPORT)"

# Kernel-checked lifecycle component; does not discharge SGV901–903.
# The driver refuses an existing directory to preserve every observation.
LEAN_REPORT ?= lean-worker-route-report
security-verify-lean:
	uv run python ../../proofs/worker-route/check.py --output "$(LEAN_REPORT)"

######################
# TESTING AND COVERAGE
######################

start-services:
	docker compose -f tests/compose-postgres.yml -f tests/compose-redis.yml up -V --force-recreate --wait --remove-orphans

stop-services:
	docker compose -f tests/compose-postgres.yml -f tests/compose-redis.yml down -v

TEST ?= .

test-fast:
	LANGGRAPH_TEST_FAST=1 uv run pytest $(TEST)

test:
	make start-services && LANGGRAPH_TEST_FAST=0 uv run --active pytest $(TEST); \
	EXIT_CODE=$$?; \
	make stop-services; \
	exit $$EXIT_CODE

test_watch:
	make start-services && LANGGRAPH_TEST_FAST=0 uv run ptw $(TEST); \
	EXIT_CODE=$$?; \
	make stop-services; \
	exit $$EXIT_CODE

######################
# LINTING AND FORMATTING
######################

# Define a variable for Python and notebook files.
PYTHON_FILES=.
lint format: PYTHON_FILES=.
lint_diff format_diff: PYTHON_FILES=$(shell git diff --name-only --relative --diff-filter=d main . | grep -E '\.py$$|\.ipynb$$')
lint_package: PYTHON_FILES=langgraph
lint_tests: PYTHON_FILES=tests

lint lint_diff lint_package lint_tests:
	uv run ruff check .
	[ "$(PYTHON_FILES)" = "" ] || uv run ruff format $(PYTHON_FILES) --diff
	[ "$(PYTHON_FILES)" = "" ] || uv run ruff check --select I $(PYTHON_FILES)
	[ "$(PYTHON_FILES)" = "" ] || uv run ty check langgraph

type:
	uv run ty check langgraph

format format_diff:
	uv run ruff format $(PYTHON_FILES)
	uv run ruff check --fix $(PYTHON_FILES)

spell_check:
	uv run codespell --toml pyproject.toml

spell_fix:
	uv run codespell --toml pyproject.toml -w


######################
# HELP
######################

help:
	@echo '===================='
	@echo '-- DOCUMENTATION --'
	
	@echo '-- LINTING --'
	@echo 'format                       - run code formatters'
	@echo 'lint                         - run linters'
	@echo 'type                         - run type checking'
	@echo 'spell_check               	- run codespell on the project'
	@echo 'spell_fix               		- run codespell on the project and fix the errors'
	@echo '-- TESTS --'
	@echo 'coverage                     - run unit tests and generate coverage report'
	@echo 'test                         - run unit tests'
	@echo 'test-fast                    - run unit tests with in-memory checkpointer only'
	@echo 'test TEST_FILE=<test_file>   - run all tests in file'
	@echo 'test_watch                   - run unit tests in watch mode'
