today=$(TZ=America/New_York date +%Y-%m-%d)
year=$(date +%Y)
url="https://epss.empiricalsecurity.com/epss_scores-${today}.csv.gz"
echo $url
response=$(curl -s -o /dev/null -w "%{http_code}" "$url")
echo $response
if [ "$response" -eq 200 ]; then
  echo "EPSS scores available for today"
else
  echo "EPSS scores not available yet for today"
  exit 1
fi
pip3 install -r code/requirements.txt
rm -f *.zip
RESPONSE=$(curl --request GET \
          --url https://api.vulncheck.com/v3/backup/nist-nvd \
          --header 'Accept: application/json' \
          --header "Authorization: Bearer $VULNCHECK_API_KEY")
url=$(echo "$RESPONSE" | jq -r '.data[0].url')
curl -L -o nvd.zip $url
unzip -o "*.zip"
rm -f *.zip
python3 -u code/process_nvd.py
