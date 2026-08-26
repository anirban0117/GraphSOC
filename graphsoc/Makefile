.PHONY: install run-backend run-frontend test seed train demo docker-up

install:
	cd backend && pip install -r requirements.txt

run-backend:
	cd backend && uvicorn app.main:app --reload --port 8000

run-frontend:
	cd frontend && python3 -m http.server 5173

test:
	cd backend && pytest -v

seed:
	curl -s -X POST http://localhost:8000/api/dev/seed -H "Content-Type: application/json" -d '{"n_benign":500,"include_attacks":true,"seed":42}'

train:
	curl -s -X POST http://localhost:8000/api/ml/train

demo:
	python3 scripts/simulate_attack.py --scenario credential_compromise_exfiltration

docker-up:
	docker compose up --build
