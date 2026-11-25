# Convenience commands. Targets for later modules are added as they are built.
# STACK picks the Terraform folder: make plan STACK=target | STACK=monitoring
STACK ?= target
TF_DIR := terraform/$(STACK)

.PHONY: init plan fmt validate

init:            ## Download providers for the chosen stack
	terraform -chdir=$(TF_DIR) init

plan: ## Show what would change in AWS (read-only, creates nothing)
	terraform -chdir=$(TF_DIR) plan -out=tfplan

fmt:             ## Format all Terraform files
	terraform fmt -recursive terraform

validate:        ## Check Terraform syntax without contacting AWS
	terraform -chdir=$(TF_DIR) validate

# Deliberately no `apply` or `destroy` target: run those by hand, on purpose:
#   terraform -chdir=terraform/target apply tfplan
#   terraform -chdir=terraform/target destroy
