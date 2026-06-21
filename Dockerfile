# ---------- WebUI build stage ----------
FROM node:20-alpine AS webui-build

WORKDIR /build
COPY webui/package.json webui/package-lock.json ./
RUN npm ci

COPY webui/ .
RUN npm run build

# ---------- Production stage ----------
FROM python:3.11-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source files (excluded items in .dockerignore)
COPY . .

# Copy built webui from build stage
COPY --from=webui-build /build/dist webui/dist

# Create data directory
RUN mkdir -p /app/agent_data

EXPOSE 1514/udp
EXPOSE 8765/tcp
EXPOSE 8766/tcp

CMD ["python3", "agent.py"]