# Endpoint-manager — the only component that touches the Docker socket.
# It is intentionally a single-purpose, isolated container:
#   - internal network only, no published ports
#   - the app itself filters every operation (allow-list), the socket mount is ro
#   - keep it small: no compilers, no shell tooling beyond python
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r requirements.txt

COPY manager.py .

EXPOSE 8001

CMD ["uvicorn", "manager:app", "--host", "0.0.0.0", "--port", "8001"]
