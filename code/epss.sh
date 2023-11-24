mkdir -p data/epss
TZ=America/New_York
today=$(date +%Y-%m-%d)
url="https://epss.cyentia.com/epss_scores-${today}.csv.gz"
echo $url
response=$(curl -s -o /dev/null -w "%{http_code}" "$url")
echo $response
if [ "$response" -eq 200 ]; then
    curl -o data/epss/epss_scores.csv.gz "$url"
    echo "EPSS scores downloaded successfully"
else
    echo "EPSS scores not available yet for today"
    exit 1
fi