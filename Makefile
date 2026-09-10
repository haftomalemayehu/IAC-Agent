fmt:
	terraform fmt -recursive

fmt-check:
	terraform fmt -check -recursive

lint:
	@echo "TFLint not installed in this environment; use a CI runner with TFLint configured."

security:
	@echo "Checkov not installed in this environment; use a CI runner with Checkov configured."

validate:
	./scripts/validate.sh

test:
	./scripts/discover.sh

plan:
	./scripts/plan.sh

cost:
	./scripts/cost.sh

ci-evidence:
	./scripts/ci-evidence.sh

verify:
	$(MAKE) fmt-check
	$(MAKE) lint
	$(MAKE) security
	$(MAKE) validate
	$(MAKE) test
	$(MAKE) plan
	$(MAKE) ci-evidence
