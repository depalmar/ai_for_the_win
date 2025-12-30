# AI for the Win - Security Training Labs
# Multi-stage Dockerfile for development and production

# =============================================================================
# Base Stage
# =============================================================================
FROM python:3.11-slim as base

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user with sudo access
RUN useradd --create-home --shell /bin/bash appuser && \
    apt-get update && apt-get install -y --no-install-recommends sudo && \
    echo "appuser ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    rm -rf /var/lib/apt/lists/*

# Set work directory
WORKDIR /app

# Declare volume for persistent workspace data
VOLUME ["/app/workspace"]

# =============================================================================
# Development Stage
# =============================================================================
FROM base as development

# Install development dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install development tools
RUN pip install --no-cache-dir \
    pytest \
    pytest-cov \
    black \
    flake8 \
    mypy \
    ipython \
    jupyter

# Copy application code
COPY --chown=appuser:appuser . .

# Switch to non-root user
USER appuser

# Default command
CMD ["python", "-m", "pytest", "tests/", "-v"]

# =============================================================================
# Production Stage
# =============================================================================
FROM base as production

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=appuser:appuser . .

# Switch to non-root user
USER appuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import anthropic; print('OK')" || exit 1

# Default command
CMD ["python", "-c", "print('AI for the Win - Ready')"]

# =============================================================================
# Jupyter Notebook Stage
# =============================================================================
FROM development as notebook

# Expose Jupyter port
EXPOSE 8888

# Start Jupyter
CMD ["jupyter", "notebook", "--ip=0.0.0.0", "--port=8888", "--no-browser", "--allow-root"]
