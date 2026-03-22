# ---- Stage 1: Build frontend ----
FROM node:20-alpine AS frontend-build

WORKDIR /app/frontend

# Copy frontend package files
COPY layers/layer5_interface_ui_ux/package.json layers/layer5_interface_ui_ux/package-lock.json* ./

RUN npm install --production=false

# Copy frontend source
COPY layers/layer5_interface_ui_ux/ ./

# Build the frontend (output goes to dist/)
RUN npm run build


# ---- Stage 2: Production image ----
FROM python:3.12-slim

WORKDIR /app

# Install gunicorn
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire Python project
COPY infrastructure/ ./infrastructure/
COPY layers/ ./layers/
COPY core_utils/ ./core_utils/
COPY simulator/ ./simulator/

# Copy built frontend into the serving location
COPY --from=frontend-build /app/frontend/dist ./layers/layer5_interface_ui_ux/dist

# Create runtime directories
RUN mkdir -p /data/storage /data/operator_storage /data/simulation_storage

# Environment variables with sensible defaults
ENV LAYER5_STORAGE_ROOT=/data/storage
ENV LAYER5_OPERATOR_STORAGE_ROOT=/data/operator_storage
ENV LAYER5_SIMULATION_ROOT=/data/simulation_storage
ENV LAYER5_ALLOWED_ORIGINS=""
ENV LAYER5_TRUST_FORWARDED_HEADERS=true
ENV PYTHONUNBUFFERED=1

# PORT is set by cloud platforms (Render uses 10000, Railway uses random)
ENV PORT=10000

EXPOSE ${PORT}

# Start gunicorn serving the WSGI app
CMD gunicorn \
    --bind "0.0.0.0:${PORT}" \
    --workers 2 \
    --timeout 120 \
    --access-logfile - \
    --error-logfile - \
    "infrastructure.layer5_api.prod_server:application"
