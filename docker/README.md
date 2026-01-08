# Docker Lab Environment

One-command setup for the AI Security Labs environment.

## Quick Start

```bash
# Start all services
docker compose up -d

# Access Jupyter Lab
open http://localhost:8888
# Token: aiforthewin
```

## Services

| Service | Port | Description |
|---------|------|-------------|
| Jupyter Lab | 8888 | Main lab environment |
| Elasticsearch | 9200 | Log storage and search |
| Kibana | 5601 | Log visualization |
| Redis | 6379 | Caching and queuing |
| MinIO | 9000/9001 | S3-compatible storage |
| PostgreSQL | 5432 | Relational database |
| Ollama | 11434 | Local LLM inference |
| ChromaDB | 8000 | Vector database |

## Service Access

### Jupyter Lab
- URL: http://localhost:8888
- Token: `aiforthewin`
- Labs available in `/home/jovyan/labs`

### Kibana
- URL: http://localhost:5601
- No authentication required

### MinIO Console
- URL: http://localhost:9001
- Username: `minioadmin`
- Password: `minioadmin123`

### PostgreSQL
- Host: localhost:5432
- Database: `security_labs`
- Username: `labuser`
- Password: `labpassword`

## Commands

### Start Services
```bash
# Start all services
docker compose up -d

# Start specific services
docker compose up -d jupyter elasticsearch

# Start with GPU support (for Ollama)
docker compose --profile gpu up -d
```

### Stop Services
```bash
# Stop all services
docker compose down

# Stop and remove volumes
docker compose down -v
```

### View Logs
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f jupyter
```

### Rebuild
```bash
# Rebuild after changes
docker compose build --no-cache

# Rebuild specific service
docker compose build jupyter
```

## Lab Profiles

### Minimal (Quick Start)
Only Jupyter and essential services:
```bash
docker compose up -d jupyter redis
```

### Log Analysis
For SIEM and log analysis labs:
```bash
docker compose up -d jupyter elasticsearch kibana
```

### Cloud Security
For cloud security labs:
```bash
docker compose up -d jupyter minio postgres
```

### AI Security
For LLM and ML security labs:
```bash
docker compose up -d jupyter ollama chromadb redis
```

### Full Stack
All services:
```bash
docker compose up -d
```

## Volume Mounts

| Container Path | Host Path | Description |
|---------------|-----------|-------------|
| /home/jovyan/labs | ./labs | Lab materials (read-only) |
| /home/jovyan/notebooks | ./notebooks | Your notebooks |
| /home/jovyan/data | ./data | Sample datasets |
| /home/jovyan/tools | ./tools | Custom tools |
| /home/jovyan/work | Docker volume | Working directory |

## GPU Support

For Ollama with GPU acceleration:

1. Install NVIDIA Container Toolkit:
```bash
# Ubuntu/Debian
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://nvidia.github.io/libnvidia-container/stable/ubuntu22.04/$(ARCH) /" | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
sudo apt-get update && sudo apt-get install -y nvidia-container-toolkit
sudo systemctl restart docker
```

2. Start with GPU:
```bash
docker compose up -d ollama
```

## Customization

### Adding Python Packages
1. Add to `requirements.txt`
2. Rebuild: `docker compose build jupyter`

### Environment Variables
Create `.env` file:
```env
JUPYTER_TOKEN=your_custom_token
POSTGRES_PASSWORD=your_password
MINIO_ROOT_PASSWORD=your_password
```

### Persistent Data
All data is stored in Docker volumes. To backup:
```bash
docker run --rm -v ai-security-labs_lab-work:/data -v $(pwd):/backup alpine tar cvf /backup/lab-work.tar /data
```

## Troubleshooting

### Port Conflicts
If ports are in use, modify `docker-compose.yml`:
```yaml
ports:
  - "8889:8888"  # Changed from 8888
```

### Memory Issues
Adjust Elasticsearch memory in `docker-compose.yml`:
```yaml
environment:
  - "ES_JAVA_OPTS=-Xms256m -Xmx256m"
```

### Permission Issues
```bash
# Fix ownership
sudo chown -R 1000:1000 ./notebooks ./data
```

### Container Won't Start
```bash
# Check logs
docker compose logs jupyter

# Remove and recreate
docker compose down
docker compose up -d
```

## Resources

- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Jupyter Docker Stacks](https://jupyter-docker-stacks.readthedocs.io/)
- [Elasticsearch Docker](https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html)
