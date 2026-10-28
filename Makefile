.PHONY: test lint smoke pilot main analyze clean
test:      ; python -m pytest -q
lint:      ; ruff check .
smoke:     ; python -m agent_safety run configs/smoke.yaml
pilot:     ; python -m agent_safety run configs/pilot.yaml
main:      ; python -m agent_safety run configs/main.yaml
analyze:   ; python -m agent_safety analyze results/$(RUN)
clean:     ; rm -rf results/smoke .pytest_cache
