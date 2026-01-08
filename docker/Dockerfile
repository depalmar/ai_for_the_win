# AI for the Win - Security Labs Environment
FROM jupyter/scipy-notebook:python-3.11

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

# Install Python packages for security labs
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Install additional ML/AI packages
RUN pip install --no-cache-dir \
    torch \
    transformers \
    sentence-transformers \
    langchain \
    langchain-community \
    openai \
    anthropic \
    chromadb \
    ollama \
    faiss-cpu

# Install security-specific packages
RUN pip install --no-cache-dir \
    yara-python \
    pefile \
    capstone \
    unicorn \
    angr \
    volatility3 \
    oletools \
    python-magic \
    ssdeep

# Install visualization packages
RUN pip install --no-cache-dir \
    plotly \
    dash \
    altair \
    bokeh \
    graphviz \
    networkx \
    pyvis

# Install data processing packages
RUN pip install --no-cache-dir \
    pandas \
    polars \
    dask \
    pyarrow \
    openpyxl \
    xlrd

# Install cloud SDKs
RUN pip install --no-cache-dir \
    boto3 \
    google-cloud-storage \
    azure-storage-blob \
    minio

# Install database connectors
RUN pip install --no-cache-dir \
    psycopg2-binary \
    elasticsearch \
    redis \
    pymongo

# Set working directory
WORKDIR /home/jovyan

# Create directory structure
RUN mkdir -p work/outputs work/models work/cache

# Set environment variables
ENV PYTHONPATH="${PYTHONPATH}:/home/jovyan/tools"
ENV JUPYTER_ENABLE_LAB=yes

# Expose Jupyter port
EXPOSE 8888

# Default command
CMD ["start-notebook.sh", "--NotebookApp.token='aiforthewin'"]
