FROM python:3.11-slim

# Preserve the same relative layout as the repo (backend/ and knowledge/
# as siblings) since app/security/attack_mapping.py and app/rag/retriever.py
# resolve the knowledge base path relative to this structure.
WORKDIR /graphsoc

COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ backend/
COPY knowledge/ knowledge/

WORKDIR /graphsoc/backend
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
