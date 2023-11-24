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
    retry_delay = 6  # seconds

    while True:
        try:
            count += 1
            response = requests.get(url, headers=headers, params=params)

            if response.status_code != 200:
                raise requests.exceptions.HTTPError(f"Failed to fetch data: {response.status_code}")

            data = response.json()
            vulnerabilities = data.get('vulnerabilities', {})
            if not vulnerabilities:
                break
            
            if count == 1:
                total_vulns = data.get('totalResults', 0)
                print(f"Total results: {total_vulns}")

            for vuln in vulnerabilities:
                #extract year from CVE ID
                year = vuln['cve']['id'].split('-')[1]

                #save each CVE by year into a file labeled with the year
                with open(f"data/nvd/nvd_vulns_{year}.json", "a", encoding='utf-8') as json_file:
                    json.dump(vuln, json_file)
                    json_file.write('\n')

            #Print total number of CVEs received so far
            print(f"Page {count} received {len(data.get('vulnerabilities', []))} CVEs")
            print(f"Total CVEs received so far: {params['startIndex'] + len(data.get('vulnerabilities', []))}")

            params['startIndex'] += len(vulnerabilities)
            if len(vulnerabilities) < params['resultsPerPage']:
                break

            time.sleep(6)  # Delay per NVD API requirements, be gentle <3

        except Exception as e:
            print(e)
            print(f"Retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)

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

def save_last_run_timestamp(filename='data/nvdlast_run.txt'):
    with open(filename, 'w') as file:
        file.write(datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'))


api_key = os.environ.get('NVD_API_KEY')
if not api_key:
    raise ValueError("NVD API key is not set.")
fetch_updates(api_key)
save_last_run_timestamp()
