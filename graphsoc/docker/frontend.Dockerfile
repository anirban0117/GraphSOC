FROM python:3.11-slim
WORKDIR /site
COPY frontend/ .
EXPOSE 5173
CMD ["python", "-m", "http.server", "5173"]
