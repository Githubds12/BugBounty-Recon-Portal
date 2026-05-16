#!/bin/bash

# Create bin directory
mkdir -p bin

# Install system dependencies
echo "Installing system dependencies..."
apt-get update && apt-get install -y libpcap-dev || echo "System dependency install failed (Normal on some Render tiers)"

echo ">> Installing Python dependencies..."
pip install -r requirements.txt

echo ">> Downloading 7-tool security chain..."

# 1. Subfinder
curl -L "https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip" -o bin/subfinder.zip
unzip -o bin/subfinder.zip -d bin/
mv bin/subfinder_2.6.6_linux_amd64/subfinder bin/subfinder 2>/dev/null || true

# 2. DNSX
curl -L "https://github.com/projectdiscovery/dnsx/releases/download/v1.2.1/dnsx_1.2.1_linux_amd64.zip" -o bin/dnsx.zip
unzip -o bin/dnsx.zip -d bin/

# 3. HTTPX
curl -L "https://github.com/projectdiscovery/httpx/releases/download/v1.6.0/httpx_1.6.0_linux_amd64.zip" -o bin/httpx.zip
unzip -o bin/httpx.zip -d bin/

# 4. Naabu (Python-Engine Fallback)
echo ">> Deploying Naabu Python-Engine..."
cp bin/naabu_engine.py bin/naabu
chmod +x bin/naabu

# 5. Katana
curl -L "https://github.com/projectdiscovery/katana/releases/download/v1.1.0/katana_1.1.0_linux_amd64.zip" -o bin/katana.zip
unzip -o bin/katana.zip -d bin/

# 6. Assetfinder
curl -L "https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz" -o bin/assetfinder.tgz
tar -xzvf bin/assetfinder.tgz -C bin/

# 7. Amass
echo ">> Installing amass..."
curl -L "https://github.com/owasp-amass/amass/releases/download/v4.2.0/amass_Linux_amd64.zip" -o bin/amass.zip
unzip -o bin/amass.zip -d bin/
# Powerful move: find the amass binary wherever it unzipped and move it to bin/amass
find bin/ -name "amass" -type f -exec mv {} bin/amass \;

# Clean up and ensure permissions
rm -f bin/*.zip bin/*.tgz
chmod +x bin/*

echo ">> Final Binary Audit:"
ls -F bin/

echo ">> Build complete. 7 tools ready."
