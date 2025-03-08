#!/bin/bash
set -e

TZ=America/New_York
today=$(date +%Y-%m-%d)
year=$(date +%Y)
url="https://epss.cyentia.com/epss_scores-${today}.csv.gz"
echo "Checking for EPSS scores at: $url"
response=$(curl -s -o /dev/null -w "%{http_code}" "$url")
echo "HTTP Response: $response"

if [ "$response" -eq 200 ]; then
  echo "EPSS scores available for today"
else
  echo "EPSS scores not available yet for today"
  echo "WARNING: Continuing with empty EPSS data for testing purposes"
fi

echo "Installing dependencies..."
pip3 install -r code/requirements.txt

echo "Cleaning up any existing zip files..."
rm -f *.zip
rm -f *.json

# Check if VULNCHECK_API_KEY is set
if [ -z "$VULNCHECK_API_KEY" ]; then
  echo "ERROR: VULNCHECK_API_KEY environment variable is not set"
  echo "Creating empty files for testing purposes"
  touch nvdcve-1.1-recent.json
else
  echo "Fetching NVD data from VulnCheck API..."
  RESPONSE=$(curl --request GET \
            --url https://api.vulncheck.com/v3/backup/nist-nvd \
            --header 'Accept: application/json' \
            --header "Authorization: Bearer $VULNCHECK_API_KEY")

  if [ $? -ne 0 ]; then
    echo "ERROR: Failed to fetch NVD data from VulnCheck API"
    echo "Creating empty files for testing purposes"
    touch nvdcve-1.1-recent.json
  else
    url=$(echo "$RESPONSE" | jq -r '.data[0].url')
    
    if [ "$url" = "null" ] || [ -z "$url" ]; then
      echo "ERROR: No download URL found in VulnCheck API response"
      echo "Creating empty files for testing purposes"
      touch nvdcve-1.1-recent.json
    else
      echo "Downloading NVD data from: $url"
      curl -L -o nvd.zip "$url"
      
      echo "Extracting NVD data..."
      unzip -o nvd.zip || {
        echo "ERROR: Failed to extract NVD data"
        echo "Creating empty files for testing purposes"
        touch nvdcve-1.1-recent.json
      }
    fi
  fi
fi

echo "Running processing script..."
python3 -u code/process_nvd.py

echo "Process completed."