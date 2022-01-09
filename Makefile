.PHONY: clean clean-test clean-pyc clean-build docs help lint black test \
	test-all dist install install-dev uninstall tags certs, type, check
.DEFAULT_GOAL := help

COVERAGE= --cov=tlsmate --cov=tlsmate/workers --cov=tlsmate/plugins
PYTEST_SUBPROCESS=$(shell pip show pytest-xdist 2&> /dev/null && echo "-n auto")

SHELL := /bin/bash

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT


help:
	@python -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

clean: clean-build clean-pyc clean-test clean-docs ## remove all build, test, docs and Python artifacts

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/

clean-docs: ## remove generated html files
	$(MAKE) -C docs clean

lint: ## check style with flake8
	flake8 tlsmate tests

black: ## check if black would reformat the python code
	black --check tlsmate tests

black-diff: ## provide the changes black would do as a diff
	black --check --diff tlsmate tests

black-reformat: ## let black reformat the python code
	black tlsmate tests

type: ## check type annotations
	mypy -p tlsmate

check: ## perform static checks (black, flake, mypy)
	$(MAKE) black && $(MAKE) lint && $(MAKE) type

certs: ## create certificates using private ca
	(cd ca && $(MAKE) all)

test: ## run tests quickly with the default Python
	py.test $(PYTEST_SUBPROCESS)

test-fast: ## run tests as quick as possible with the default Python
	TLSMATE_RECORDER_DELAY=0 py.test $(PYTEST_SUBPROCESS)

tags: ## generate ctags
	ctags -R --languages=python  -f ./tags tlsmate/ tests/

test-cov: ## generate coverage statistics
	py.test $(COVERAGE) $(PYTEST_SUBPROCESS)

test-cov-report: ## generate coverage report for each file
	py.test --cov-report annotate:cov_annotate $(COVERAGE) $(PYTEST_SUBPROCESS)

test-all: ## run tests on every Python version with tox
	tox

docs: clean-docs ## generate Sphinx HTML documentation, including API docs
	$(MAKE) -C docs html

dist: clean ## builds source and wheel package
	python setup.py sdist
	python setup.py bdist_wheel
	ls -l dist

install: ## install the package using pip
	pip install .

install-dev: ## install the package using the development environment
	pip install -e .[dev]

uninstall: ## uninstall the package using pip
	pip uninstall tlsmate
