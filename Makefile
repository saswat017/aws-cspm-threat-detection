# Convenience commands (Linux/macOS/Git Bash). On Windows PowerShell use .\make.ps1 <target>.
# Every target is a plain `python -m ...` or `terraform ...` command, so you can also run it directly.
#
# CSPM_MODE=demo (default) uses the local AWS emulator; CSPM_MODE=live uses real AWS.
STACK ?= target
PY    ?= python

.PHONY: help install lab-up lab-down lab-status init plan scan diff report detect watch \
        simulate revert mttd dashboard test

help:      ## list targets
	@grep -E '^[a-z-]+:.*##' Makefile | sed 's/:.*##/\t/'

install:   ## install Python dependencies
	$(PY) -m pip install -r requirements.txt

lab-up:    ## start the AWS emulator and deploy terraform/target + monitoring into it
	$(PY) -m lab up

lab-down:  ## stop the emulator
	$(PY) -m lab down

lab-status: ## what is running/deployed in the emulator
	$(PY) -m lab status

init:      ## terraform init for STACK (real AWS)
	terraform -chdir=terraform/$(STACK) init

plan:      ## terraform plan for STACK against REAL AWS (read-only)
	terraform -chdir=terraform/$(STACK) plan -out=tfplan

scan:      ## posture scan (custom checks + Prowler in live mode)
	$(PY) -m scanner scan

diff:      ## new/resolved findings between the last two scans (drift)
	$(PY) -m scanner diff

report:    ## HTML assessment report
	$(PY) -m scanner report

detect:    ## run the detection engine once
	$(PY) -m detection run

watch:     ## run the detection engine continuously
	$(PY) -m detection watch

simulate:  ## run every attack scenario (SCENARIO=name for one)
	$(PY) -m simulation run $(or $(SCENARIO),all)

revert:    ## undo the attack scenarios
	$(PY) -m simulation revert $(or $(SCENARIO),all)

mttd:      ## mean time to detect per scenario
	$(PY) -m simulation mttd

dashboard: ## Streamlit dashboard
	$(PY) -m streamlit run dashboard/app.py

test:      ## unit tests (moto, no AWS needed)
	$(PY) -m pytest -q

# Deliberately no apply/destroy target for REAL AWS. Run those by hand, on purpose:
#   terraform -chdir=terraform/target apply tfplan
