from datetime import datetime, date
import os
import pandas as pd
import enrich_nvd
import json

EPSS_CSV = f'https://epss.cyentia.com/epss_scores-{date.today()}.csv.gz'
TIMESTAMP_FILE = './code/last_run.txt'


def process_nvd_files():
    """
    Processes the NVD JSON files and returns a dataframe.

    Returns:
        nvd_df: A dataframe containing the NVD data.
    """
    nvd_accumulator = []
    for f in os.listdir():
        if f.endswith('.json'):
            print(f'Processing {f}')
            with open(f'{f}', 'r', encoding='utf-8') as ff:
                data = json.load(ff)
                vulnerabilities = data.get('CVE_Items', {})
                for entry in vulnerabilities:
                    description = entry['cve']['description']['description_data'][0]['value']
                    cve = entry['cve']['CVE_data_meta']['ID']
                    assigner = entry['cve']['CVE_data_meta']['ASSIGNER']
                    published_date = entry['publishedDate']
                    if entry['impact'].get('baseMetricV3'):
                        cvss_version = entry['impact']['baseMetricV3']['cvssV3']['version']
                        base_score = entry['impact']['baseMetricV3']['cvssV3']['baseScore']
                        base_severity = entry['impact']['baseMetricV3']['cvssV3']['baseSeverity']
                        base_vector = entry['impact']['baseMetricV3']['cvssV3']['vectorString']
                    elif entry['impact'].get('baseMetricV2'):
                        cvss_version = entry['impact']['baseMetricV2']['cvssV2']['version']
                        base_score = entry['impact']['baseMetricV2']['cvssV2']['baseScore']
                        base_severity = entry['impact']['baseMetricV2']['severity']
                        base_vector = entry['impact']['baseMetricV2']['cvssV2']['vectorString']
                    new_row = {
                        'cve': cve,
                        'cvss_version': cvss_version,
                        'base_score': base_score,
                        'base_severity': base_severity,
                        'base_vector': base_vector,
                        'assigner': assigner,
                        'published_date': published_date
                    }
                    if not description.startswith('**'):
                        nvd_accumulator.append(new_row)

    nvd_df = pd.DataFrame(nvd_accumulator)
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
