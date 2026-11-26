.PHONY: install test lint serve demo data clean

install:
	pip install -e ".[dev]"

test:
	pytest -v

lint:
	ruff check src tests scripts

serve:
	stixflow serve --port 5000

data:
	python scripts/generate_sample_data.py

# Full pipeline against the local demo server (run `make serve` in another terminal first)
demo:
	stixflow discover http://127.0.0.1:5000
	stixflow pull http://127.0.0.1:5000
	stixflow stats
	stixflow pivot 203.0.113.45 --depth 3
	mkdir -p reports
	stixflow hunt samples/plant_firewall.log --report reports/hunt_report.md
	stixflow export -f txt -o reports/blocklist.txt

clean:
	rm -rf *.db reports .pytest_cache .ruff_cache
