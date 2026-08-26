FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY skylight_mcp_server.py .

# Railway injects PORT at runtime; the app reads it via os.environ.
EXPOSE 8000

CMD ["python", "skylight_mcp_server.py"]
