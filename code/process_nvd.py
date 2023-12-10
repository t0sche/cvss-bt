from datetime import datetime, date
import time
import os
import requests
import pandas as pd
import enrich_nvd

EPSS_CSV = f'https://epss.cyentia.com/epss_scores-{date.today()}.csv.gz'
TIMESTAMP_FILE = './code/last_run.txt'


def fetch_updates(api_key, last_mod_start_date=None):
    """
    Fetches updates from the NVD API and processes the data.

    Args:
        api_key (str): The API key for accessing the NVD API.
        last_mod_start_date (str, optional): The start date for filtering the updates. Defaults to None.

    Returns:
        None
    """
    

    if last_mod_start_date:
        print(f'Fetching updates from NVD API since last run at {last_mod_start_date}')
        params = {
            'resultsPerPage': 1000,
            'startIndex': 0,
            'lastModStartDate': last_mod_start_date,
            'lastModEndDate': datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')
        }
    else:
        print(f'Fetching all data from NVD API. This may take a while.')
        print(f'{last_mod_start_date}')
        params = {
            'resultsPerPage': 1000,
            'startIndex': 0
        }

    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0?noRejected'
    headers = {'API-Key': api_key}
    count = 0
    retry_delay = 6  # seconds
    nvd_accumulator = []

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

            for entry in vulnerabilities:
                
                cve = entry['cve']['id']

                highest_cvss_data = ''
                if "cvssMetricV4" in entry['cve']['metrics']:
                    highest_cvss_data = "cvssMetricV4"
                elif "cvssMetricV31" in entry['cve']['metrics']:
                    highest_cvss_data = "cvssMetricV31"
                elif "cvssMetricV30" in entry['cve']['metrics']:
                    highest_cvss_data = "cvssMetricV30"
                elif "cvssMetricV2" in entry['cve']['metrics']:
                    highest_cvss_data = "cvssMetricV2"
                if not highest_cvss_data:
                    continue  # skip if no CVSS data
                cvss_data_gen_primary = ((x, x['cvssData']) for x in entry['cve']['metrics'][highest_cvss_data] if x['type'] == 'Primary')
                cvss_data_gen_secondary = ((x, x['cvssData']) for x in entry['cve']['metrics'][highest_cvss_data] if x['type'] == 'Secondary')
                try:
                    cvss_data, cvss_vector = next(cvss_data_gen_primary)
                except StopIteration:
                    cvss_data, cvss_vector  = next(cvss_data_gen_secondary)
                cvss_version = cvss_vector.get('version', '')
                base_score = cvss_vector.get('baseScore', '')
                if cvss_version == '2.0':
                    base_severity = cvss_data.get('baseSeverity', '')
                else:
                    base_severity = cvss_vector.get('baseSeverity', '')

                base_vector = cvss_vector.get('vectorString', '')
                new_row = {
                    'cve': cve,
                    'cvss_version': cvss_version,
                    'base_score': base_score,
                    'base_severity': base_severity,
                    'base_vector': base_vector,
                    'nvd_last_updated': entry['cve']['lastModified']
                }
                if cvss_version:
                    nvd_accumulator.append(new_row)

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

    nvd_df = pd.DataFrame(nvd_accumulator)
    print('CVEs with CVSS scores from NVD:', nvd_df['cve'].nunique())

    # Error handling when nvd_df is empty
    if not nvd_df.empty:
        # Logic to deal with if we are generating a new csv or updating an existing one. The CSV is an output of nvd_df, so we need to make sure we are only updating CVEs to the CSV and adding them if they don't exist.
        if os.path.isfile('cvss-bt.csv'):
            print('Updating existing CSV')
            existing_df = pd.read_csv('cvss-bt.csv')
            columns_to_keep = [
                'cve',
                'cvss_version',
                'base_score',
                'base_severity',
                'base_vector',
                'nvd_last_updated'
            ]

            existing_df = existing_df[columns_to_keep]
            print(f'Existing DF Shape: {existing_df.shape}')
            existing_df.columns = existing_df.columns.str.strip()
            print(f'Existing DF Columns: {existing_df.columns.to_list()}')
            
            print(f'Incomcing DF Shape: {nvd_df.shape}')
            print(f'Incoming DF Columns: {nvd_df.columns.to_list()}')

            # Use combine_first to fill in values from nvd_df where existing_df has NaNs
            combined_df = nvd_df.combine_first(existing_df)

        else:
            print('Creating new CSV')
            combined_df = nvd_df
            
        # Logic to enrich the data with exploit maturity and temporal scores.
        print('Enriching data')
        enriched_df = enrich_nvd.enrich(combined_df, pd.read_csv(EPSS_CSV, comment='#', compression='gzip'))
        cvss_bt_df = enrich_nvd.update_temporal_score(enriched_df, enrich_nvd.EPSS_THRESHOLD)

        columns = [
            'cve',
            'cvss-bt_score',
            'cvss-bt_severity',
            'cvss-bt_vector',
            'cvss_version',
            'base_score',
            'base_severity',
            'base_vector',
            'nvd_last_updated',
            'epss',
            'cisa_kev',
            'exploitdb',
            'metasploit',
            'nuclei'
        ]

        cvss_bt_df = cvss_bt_df[columns]

        cvss_bt_df.to_csv('cvss-bt.csv', index=False, mode='w')
    else:
        print('No new CVEs found')
        #Re-enrich the data to update the temporal scores
        print('Re-enriching data and re-scoring CVEs')

        columns_to_keep = [
            'cve',
            'cvss_version',
            'base_score',
            'base_severity',
            'base_vector',
            'nvd_last_updated'
        ]

        existing_cvss_bt_df = cvss_bt_df[columns_to_keep]

        enriched_df = enrich_nvd.enrich(existing_cvss_bt_df, pd.read_csv(EPSS_CSV, comment='#', compression='gzip'))
        cvss_bt_df = enrich_nvd.update_temporal_score(enriched_df, enrich_nvd.EPSS_THRESHOLD)

        columns = [
            'cve',
            'cvss-bt_score',
            'cvss-bt_severity',
            'cvss-bt_vector',
            'cvss_version',
            'base_score',
            'base_severity',
            'base_vector',
            'nvd_last_updated',
            'epss',
            'cisa_kev',
            'exploitdb',
            'metasploit',
            'nuclei'
        ]

        cvss_bt_df = cvss_bt_df[columns]

        cvss_bt_df.to_csv('cvss-bt.csv', index=False, mode='w')


def save_last_run_timestamp(filename='last_run.txt'):
    """
    Save the current timestamp as the last run timestamp in a file.

    Args:
        filename (str): The name of the file to save the timestamp. Default is 'last_run.txt'.
    """
    with open(filename, 'w') as f:
        f.write(datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'))



nvd_key = os.environ.get('NVD_API_KEY')
if not nvd_key:
    raise ValueError("NVD API key is not set.")

LAST_RUN = None
if os.path.exists(TIMESTAMP_FILE):
    with open(TIMESTAMP_FILE, 'r') as file:
        LAST_RUN = file.readline().strip()
        

fetch_updates(nvd_key, LAST_RUN)
save_last_run_timestamp(TIMESTAMP_FILE)
