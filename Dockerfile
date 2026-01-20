# AI for the Win - Security Training Labs
# Multi-stage Dockerfile for development and production

# =============================================================================
# Base Stage
# =============================================================================
# Pin base image with SHA256 digest for reproducibility (OpenSSF Scorecard)
FROM python:3.11-slim@sha256:7ad180fdf785219c4a23124e53745fbd683bd6e23d0885e3554aff59eddbc377 as base

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

# Install Python dependencies (pin pip first for reproducibility)
RUN pip install pip==24.3.1 && pip install --no-cache-dir -r requirements.txt

# Install development tools (versions pinned for reproducibility)
RUN pip install --no-cache-dir \
    pytest==9.0.2 \
    pytest-cov==7.0.0 \
    black==25.12.0 \
    flake8==7.3.0 \
    mypy==1.14.1 \
    ipython==8.31.0 \
    jupyter==1.1.1

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

# Install Python dependencies (pin pip first for reproducibility)
RUN pip install pip==24.3.1 && pip install --no-cache-dir -r requirements.txt

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
