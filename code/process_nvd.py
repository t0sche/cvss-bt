from datetime import datetime
import json
import os
import pandas as pd


BASE_NVD_FILE_PATH = r'data/nvd/nvd_vulns_{year}.json'


def process_nvd():
    """
    Process NVD files from 1999 to current year
    """
    row_accumulator = []
    current_year = datetime.now().year
    for year in range(1999, current_year + 1):
        if not os.path.exists(BASE_NVD_FILE_PATH.replace('{year}', str(year))):
            print(f"File for {year} not found")
        else:
            print(BASE_NVD_FILE_PATH.replace('{year}', str(year)))
            with open(BASE_NVD_FILE_PATH.replace('{year}', str(year))) as f:
                nvd_data = json.load(f)
                for entry in nvd_data:
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
                        'base_vector': base_vector
                    }
                    if cvss_version:
                        row_accumulator.append(new_row)

    nvd = pd.DataFrame(row_accumulator)
    print ('CVEs with CVSS scores from NVD:', nvd['cve'].nunique())
    return nvd

if __name__ == '__main__':

    nvd_df = process_nvd()
    nvd_df = nvd_df.drop_duplicates(subset=['cve'])
    nvd_df.to_csv('data/nvd.csv', index=False)
