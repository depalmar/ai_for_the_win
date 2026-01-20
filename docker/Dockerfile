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

# Install additional ML/AI packages (versions pinned for reproducibility)
RUN pip install --no-cache-dir \
    torch==2.5.1 \
    transformers==4.47.1 \
    sentence-transformers==3.3.1 \
    langchain==0.3.14 \
    langchain-community==0.3.14 \
    openai==1.58.1 \
    anthropic==0.42.0 \
    chromadb==0.5.23 \
    ollama==0.4.5 \
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
ENV PYTHONPATH="${PYTHONPATH}:/home/jovyan/tools"
ENV JUPYTER_ENABLE_LAB=yes

# Expose Jupyter port
EXPOSE 8888

# Default command
CMD ["start-notebook.sh", "--NotebookApp.token='aiforthewin'"]
