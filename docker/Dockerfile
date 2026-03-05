# AI for the Win - Security Labs Environment
# Pin base image with SHA256 digest for reproducibility (OpenSSF Scorecard)
# Note: Jupyter images moved to quay.io as of Oct 2023
FROM quay.io/jupyter/scipy-notebook:2024-12-09@sha256:210513fd13a22a9477d48d61c09d49affd82a2fe2ee53b2bde9de67238db9890

LABEL maintainer="AI for the Win"
LABEL description="Security-focused data science and ML environment"

USER root

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    wget \
    vim \
    jq \
    yara \
    libmagic1 \
    nmap \
    netcat-openbsd \
    tcpdump \
    tshark \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Volatility 3 dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-dev \
    libpython3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

USER ${NB_UID}

# Install Python packages for security labs (pin pip first for reproducibility)
COPY requirements.txt /tmp/requirements.txt
RUN pip install pip==24.3.1 && pip install --no-cache-dir -r /tmp/requirements.txt

# Install additional ML/AI packages (versions pinned for reproducibility)
# Note: chromadb must be >=1.0.0 to avoid tokenizers conflict with transformers
RUN pip install --no-cache-dir \
    torch==2.6.0 \
    transformers==4.48.3 \
    sentence-transformers==5.0.0 \
    langchain==1.0.0 \
    langchain-community==0.3.20 \
    openai==1.66.3 \
    anthropic==0.49.0 \
    chromadb==1.0.12 \
    ollama==0.4.7 \
    faiss-cpu==1.9.0.post1

# Install security-specific packages (versions pinned for reproducibility)
RUN pip install --no-cache-dir \
    yara-python==4.5.1 \
    pefile==2024.8.26 \
    capstone==5.0.3 \
    unicorn==2.1.1 \
    angr==9.2.133 \
    volatility3==2.11.0 \
    oletools==0.60.2 \
    python-magic==0.4.27 \
    ssdeep==3.4

# Install visualization packages (versions pinned for reproducibility)
RUN pip install --no-cache-dir \
    plotly==5.24.1 \
    dash==2.18.2 \
    altair==5.5.0 \
    bokeh==3.6.2 \
    graphviz==0.20.3 \
    networkx==3.4.2 \
    pyvis==0.3.2

# Install data processing packages (versions pinned for reproducibility)
RUN pip install --no-cache-dir \
    pandas==2.2.3 \
    polars==1.18.0 \
    dask==2024.12.1 \
    pyarrow==18.1.0 \
    openpyxl==3.1.5 \
    xlrd==2.0.1

# Install cloud SDKs (versions pinned for reproducibility)
RUN pip install --no-cache-dir \
    boto3==1.35.93 \
    google-cloud-storage==2.19.0 \
    azure-storage-blob==12.24.0 \
    minio==7.2.12

# Install database connectors (versions pinned for reproducibility)
RUN pip install --no-cache-dir \
    psycopg2-binary==2.9.10 \
    elasticsearch==8.17.0 \
    redis==5.2.1 \
    pymongo==4.10.1

# Set working directory
WORKDIR /home/jovyan

# Create directory structure
RUN mkdir -p work/outputs work/models work/cache

# Set environment variables
ENV PYTHONPATH="${PYTHONPATH}:/home/jovyan/shared"
ENV JUPYTER_ENABLE_LAB=yes

# Expose Jupyter port
EXPOSE 8888

# Default command
CMD ["start-notebook.sh", "--NotebookApp.token='aiforthewin'"]
