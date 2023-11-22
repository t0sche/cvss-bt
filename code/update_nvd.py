from datetime import datetime
import json
import time
import sys
import os
import requests


def fetch_updates(api_key):
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected'
    headers = {'API-Key': api_key}

    params = {
        'resultsPerPage': 1000,
        'startIndex': 0
    }

    count = 0
    max_retries = 5
    retry_delay = 10  # seconds

    while True:
        try:
            import requests.exceptions

            count += 1
            response = requests.get(url, headers=headers, params=params)

            if response.status_code != 200:
                raise requests.exceptions.HTTPError(f"Failed to fetch data: {response.status_code}")

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', {})
            if not vulnerabilities:
                break

            params['startIndex'] += len(vulnerabilities)
            if len(vulnerabilities) < params['resultsPerPage']:
                break

            time.sleep(6)  # Delay for 6 seconds between requests per NVD guidance

        except Exception as e:
            print(e)
            if max_retries > 0:
                max_retries -= 1
                print(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print("Maximum retries reached. Exiting.")
                sys.exit(1)

    for year in range(1999, datetime.now().year + 1):
        reformat_json_file(f'data/nvd/nvd_vulns_{year}.json')


def reformat_json_file(file_path):
    try:
        with open(file_path, 'r') as file:
            # Read line-separated JSON objects into a list
            data = [json.loads(line) for line in file]

        with open(file_path, 'w') as file:
            # Write the list as a JSON array
            json.dump(data, file, indent=4)
    except Exception as e:
        print(f"Error occurred while reformating JSON file: {e}")

api_key = os.environ.get('NVD_API_KEY')
if not api_key:
    raise ValueError("NVD API key is not set.")
fetch_updates(api_key)
