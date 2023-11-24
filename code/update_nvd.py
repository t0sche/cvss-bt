from datetime import datetime
import json
import time
import sys
import os
import requests
import collections


def fetch_updates(api_key, last_mod_start_date):
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected'
    headers = {'API-Key': api_key}

    params = {
        'resultsPerPage': 200,
        'startIndex': 0,
        'lastModStartDate': last_mod_start_date,
        'lastModEndDate': datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
    }

    count = 0
    max_retries = 5
    retry_delay = 10  # seconds

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
                
            # Load all JSON files into a dictionary in memory
            data_col = collections.defaultdict(list)
            for year in range(1999, datetime.today().year):
                file_path = f"data/nvd/nvd_vulns_{year}.json"
                if os.path.exists(file_path):
                    with open(file_path, 'r', encoding='utf-8') as json_file:
                        data[year] = json.load(json_file)

            for vuln in vulnerabilities:
            # Extract year from CVE ID
                year = int(vuln['cve']['id'].split('-')[1])

                # Find the index of the existing entry with the same CVE ID as the new data, if it exists
                index = next((index for (index, d) in enumerate(data_col[year]) if d['cve']['id'] == vuln['cve']['id']), None)

                # If an existing entry was found, replace it with the new data
                if index is not None:
                    print(f"Updating CVE data: {vuln['cve']['id']}")
                    data_col[year][index] = vuln
                # Otherwise, add the new data to the end of the list
                else:
                    print(f"Adding new CVE data: {vuln['cve']['id']}")
                    data_col[year].append(vuln)

            # Write the updated data back to the JSON files
            for year, vulns in data_col.items():
                file_path = f"data/nvd/nvd_vulns_{year}.json"
                with open(file_path, 'w', encoding='utf-8') as json_file:
                    json.dump(vulns, json_file, ensure_ascii=False)

            #Print total number of CVEs received so far
            print(f"Page {count} received {len(data.get('vulnerabilities', []))} CVEs")
            print(f"Total CVEs received so far: {params['startIndex'] + len(data.get('vulnerabilities', []))}")

            params['startIndex'] += len(vulnerabilities)
            if len(vulnerabilities) < params['resultsPerPage']:
                break

            time.sleep(6)  # Delay per NVD API requirements

        except Exception as e:
            print(e)
            if max_retries > 0:
                max_retries -= 1
                print(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print("Maximum retries reached. Exiting.")
                sys.exit(1)

        
def read_last_run_timestamp(filename='last_run.txt'):
    try:
        with open(filename, 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        return None

def save_last_run_timestamp(filename='last_run.txt'):
    with open(filename, 'w') as file:
        file.write(datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'))


api_key = os.environ.get('NVD_API_KEY')
if not api_key:
    raise ValueError("NVD API key is not set.")
fetch_updates(api_key, read_last_run_timestamp())
save_last_run_timestamp()
