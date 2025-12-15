# Installation Guide

This guide covers detailed installation instructions for Inferno-AI.

## Table of Contents

- [System Requirements](#system-requirements)
- [Quick Install](#quick-install)
- [Step-by-Step Installation](#step-by-step-installation)
- [Docker Installation](#docker-installation)
- [Troubleshooting](#troubleshooting)

## System Requirements

### Operating System

| OS | Status | Notes |
|----|--------|-------|
| macOS 12+ | Fully Supported | Best experience, Claude Code OAuth via Keychain |
| Ubuntu 22.04+ | Fully Supported | Use ENV OAuth token or API key |
| Debian 12+ | Fully Supported | Use ENV OAuth token or API key |
| Kali Linux | Fully Supported | Security tools pre-installed |
| Windows 11 | Fully Supported | Via Docker or WSL2 (recommended) |
| Windows 10 | Supported | Via Docker or WSL2 |
| Other Linux | Should Work | May need manual tool installation |

### Hardware

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores |
| RAM | 8 GB | 16 GB |
| Disk | 10 GB | 20 GB |
| Network | Required | Stable connection |

### Software Dependencies

- **Python 3.11+** - Core runtime
- **Docker** - For Qdrant memory backend
- **Git** - For cloning and updates

## Quick Install

```bash
# One-liner for quick setup (requires Python 3.11+ and Docker)
git clone https://github.com/Adem035/Inferno.git && \
cd Inferno && \
python -m venv venv && \
source venv/bin/activate && \
pip install -e . && \
docker run -d -p 6333:6333 qdrant/qdrant && \
inferno setup
```

## Step-by-Step Installation

### 1. Install Python 3.11+

**macOS (using Homebrew):**
```bash
brew install python@3.11
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip
```

**Verify installation:**
```bash
python3 --version  # Should show 3.11.x or higher
```

### 2. Install Docker

**macOS:**
```bash
brew install --cask docker
# Then open Docker Desktop from Applications
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install docker.io docker-compose
sudo usermod -aG docker $USER
# Log out and back in for group changes
```

**Verify Docker:**
```bash
docker --version
docker run hello-world
```

### 3. Clone Inferno

```bash
git clone https://github.com/Adem035/Inferno.git
cd Inferno
```

### 4. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 5. Install Inferno

```bash
# Standard installation
pip install -e .

# With development dependencies
pip install -e ".[dev]"
```

### 6. Start Qdrant (Memory Backend)

Qdrant provides persistent vector memory for the agent.

**Using Docker (Recommended):**
```bash
docker run -d \
  --name inferno-qdrant \
  -p 6333:6333 \
  -v qdrant_data:/qdrant/storage \
  qdrant/qdrant
```

**Using Docker Compose:**
```bash
docker-compose up -d qdrant
```

**Verify Qdrant:**
```bash
curl http://localhost:6333/healthz
# Should return: {"title":"qdrant - vectorass engine","version":"..."}
```

### 7. Run Setup

The setup command validates your environment and helps install security tools:

```bash
inferno setup
```

This will:
- Check Python version
- Verify Qdrant connection
- Check for required security tools
- Offer to install missing tools (via brew/apt)
- Validate API credentials

### 8. Configure Authentication

See [AUTHENTICATION.md](AUTHENTICATION.md) for detailed instructions.

**Quick setup:**

```bash
# Option A: If you have Claude Code CLI (macOS)
claude login  # Login once, Inferno reuses the token

# Option B: API Key
export ANTHROPIC_API_KEY=sk-ant-...
```

### 9. Verify Installation

```bash
# Check Inferno is installed
inferno --help

# Run a quick test
inferno shell
# In shell: target https://example.com
# In shell: status
```

## Windows Installation

### Option A: Docker Desktop (Recommended for Windows)

The easiest way to run Inferno on Windows with all security tools included.

**Step 1: Install Docker Desktop**
1. Download from [docker.com/products/docker-desktop](https://www.docker.com/products/docker-desktop/)
2. Run the installer
3. Restart your computer when prompted
4. Open Docker Desktop and wait for it to start

**Step 2: Clone Inferno**
```powershell
git clone https://github.com/Adem035/Inferno.git
cd Inferno
```

**Step 3: Create .env file**
```powershell
# Copy example and edit with your credentials
copy .env.example .env
notepad .env
```

Add your authentication (choose one):
```
# Option 1: API Key
ANTHROPIC_API_KEY=sk-ant-api03-...

# Option 2: OAuth Token (uses your Claude subscription - FREE)
CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-...
```

**Step 4: Start Inferno**
```powershell
docker-compose up -d
docker-compose exec inferno bash
inferno shell
```

### Option B: WSL2 (Windows Subsystem for Linux)

For a native Linux experience on Windows.

**Step 1: Enable WSL2**
```powershell
# Run PowerShell as Administrator
wsl --install -d Ubuntu
```

Restart your computer, then set up Ubuntu with a username/password.

**Step 2: Install Dependencies in WSL**
```bash
# In Ubuntu terminal
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip docker.io git

# Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

**Step 3: Clone and Install**
```bash
git clone https://github.com/Adem035/Inferno.git
cd Inferno
python3.11 -m venv venv
source venv/bin/activate
pip install -e .
```

**Step 4: Start Qdrant**
```bash
docker run -d -p 6333:6333 --name inferno-qdrant qdrant/qdrant
```

**Step 5: Set Authentication**
```bash
# Add to ~/.bashrc
echo 'export CLAUDE_CODE_OAUTH_TOKEN=sk-ant-oat01-your-token' >> ~/.bashrc
source ~/.bashrc

# Or use API key
echo 'export ANTHROPIC_API_KEY=sk-ant-api03-your-key' >> ~/.bashrc
source ~/.bashrc
```

**Step 6: Run Inferno**
```bash
inferno setup
inferno shell
```

### Windows-Specific Notes

- **Security Tools**: All tools run inside Docker container - no need to install nmap, sqlmap, etc. on Windows
- **Authentication**: Use `CLAUDE_CODE_OAUTH_TOKEN` or `ANTHROPIC_API_KEY` environment variables
- **File Paths**: Use forward slashes in paths even on Windows when inside Docker/WSL
- **Performance**: Docker on Windows may be slower than native Linux; WSL2 offers better performance

## Docker Installation (All Platforms)

You can run Inferno entirely in Docker:

```bash
# Build the image
docker build -t inferno-ai .

# Run with Docker Compose (includes Qdrant)
docker-compose up -d

# Enter the container
docker-compose exec inferno bash
inferno shell
```

### Docker Compose Services

The `docker-compose.yml` includes:

| Service | Port | Description |
|---------|------|-------------|
| inferno | - | Main agent container |
| qdrant | 6333 | Vector database |
| grafana | 3000 | Metrics dashboard (optional) |
| prometheus | 9090 | Metrics collection (optional) |

**Start with monitoring:**
```bash
docker-compose --profile monitoring up -d
```

## Installing Security Tools

Inferno needs external security tools installed on your system. The `inferno setup` command will help install them.

### Automatic Installation

```bash
inferno setup --install-tools
```

### Manual Installation

**macOS:**
```bash
brew install nmap masscan gobuster nikto sqlmap hydra
brew install --cask burp-suite  # Optional
```

**Ubuntu/Debian/Kali:**
```bash
sudo apt update
sudo apt install nmap masscan gobuster nikto sqlmap hydra
```

**Full tool list:** See [TOOLS.md](TOOLS.md)

## Troubleshooting

### Python Version Issues

```bash
# Check version
python3 --version

# If wrong version, use specific version
python3.11 -m venv venv
```

### Qdrant Connection Failed

```bash
# Check if running
docker ps | grep qdrant

# Restart if needed
docker restart inferno-qdrant

# Check logs
docker logs inferno-qdrant
```

### Permission Denied (Docker)

```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Apply changes (or logout/login)
newgrp docker
```

### Import Errors

```bash
# Reinstall in editable mode
pip install -e . --force-reinstall
```

### API Key Not Found

```bash
# Check environment variable
echo $ANTHROPIC_API_KEY

# Or check keychain (macOS)
security find-generic-password -s "Claude Code-credentials" -a "$USER" -w
```

### Tools Not Found

```bash
# Check if tool is in PATH
which nmap

# Install missing tools
inferno setup --install-tools
```

## Updating Inferno

```bash
cd Inferno
git pull origin main
pip install -e . --upgrade
```

## Uninstalling

```bash
# Remove virtual environment
rm -rf venv

# Stop and remove Docker containers
docker-compose down -v

# Remove Qdrant data
docker volume rm qdrant_data

# Remove the directory
cd ..
rm -rf inferno-ai
```

## Next Steps

- [Configure Authentication](AUTHENTICATION.md)
- [Configure Settings](CONFIGURATION.md)
- [Learn CLI Usage](USAGE.md)
