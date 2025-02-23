from datetime import datetime, date
from pathlib import Path
import pandas as pd
import enrich_nvd, create_sankey
import json

EPSS_CSV = f'https://epss.cyentia.com/epss_scores-{date.today()}.csv.gz'
TIMESTAMP_FILE = './code/last_run.txt'


def process_nvd_files():
    """
    Processes the NVD JSON files and returns a dataframe.

    Returns:
        nvd_df: A dataframe containing the NVD data.
    """
    nvd_dict = []

    for file_path in Path('.').glob('*.json'):
        print(f'Processing {file_path.name}')
        with file_path.open('r', encoding='utf-8') as file:
            data = json.load(file)
            vulnerabilities = data.get('CVE_Items', [])
            print(f'CVEs in {file_path.name}:', len(vulnerabilities))

            for entry in vulnerabilities:
                if not entry['cve']['description']['description_data'][0]['value'].startswith('**'):
                    cve = entry['cve']['CVE_data_meta']['ID']
                    if 'metricV40' in entry['impact']:
                        cvss_version = '4.0'
                        base_score = entry['impact']['metricV40']['baseScore']
                        base_severity = entry['impact']['metricV40']['baseSeverity']
                        base_vector = entry['impact']['metricV40']['vectorString']
                    elif 'baseMetricV3' in entry['impact']:
                        cvss_version = entry['impact']['baseMetricV3']['cvssV3']['version']
                        base_score = entry['impact']['baseMetricV3']['cvssV3']['baseScore']
                        base_severity = entry['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                        base_vector = entry['impact']['baseMetricV3']['cvssV3']['vectorString']
                    else:
                        cvss_version = entry['impact'].get('baseMetricV2', {}).get('cvssV2', {}).get('version', 'N/A')
                        base_score = entry['impact'].get('baseMetricV2', {}).get('cvssV2', {}).get('baseScore', 'N/A')
                        base_severity = entry['impact'].get('baseMetricV2', {}).get('severity', 'N/A')
                        base_vector = entry['impact'].get('baseMetricV2', {}).get('cvssV2', {}).get('vectorString', 'N/A')
                    assigner = entry['cve']['CVE_data_meta']['ASSIGNER']
                    published_date = entry['publishedDate']
                    description = entry['cve']['description']['description_data'][0]['value']

                    dict_entry = {
                        'cve': cve,
                        'cvss_version': cvss_version,
                        'base_score': base_score,
                        'base_severity': base_severity,
                        'base_vector': base_vector,
                        'assigner': assigner,
                        'published_date': published_date,
                        'description': description
                    }
                    nvd_dict.extend([dict_entry])


    nvd_df = pd.DataFrame(nvd_dict)
    print('CVEs with CVSS scores from NVD:', nvd_df['cve'].nunique())

    return nvd_df


def enrich_df(nvd_df):
    """
    Enriches the dataframe with exploit maturity and temporal scores.
    """

    print('Enriching data')
    enriched_df = enrich_nvd.enrich(nvd_df, pd.read_csv(EPSS_CSV, comment='#', compression='gzip'))
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
        'assigner',
        'published_date',
        'epss',
        'cisa_kev',
        'vulncheck_kev',
        'exploitdb',
        'metasploit',
        'nuclei',
        'poc_github'
    ]
    cvss_bt_df = cvss_bt_df[columns]
    cvss_bt_df = cvss_bt_df.sort_values(by=['published_date'])
    cvss_bt_df = cvss_bt_df.reset_index(drop=True)
    cvss_bt_df.to_csv('cvss-bt.csv', index=False, mode='w')


def save_last_run_timestamp(filename='last_run.txt'):
    """
    Save the current timestamp as the last run timestamp in a file.

    Args:
        filename (str): The name of the file to save the timestamp. Default is 'last_run.txt'.
    """
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'))


enrich_df(process_nvd_files())
save_last_run_timestamp(TIMESTAMP_FILE)
