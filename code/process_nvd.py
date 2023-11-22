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
    for year in range(1999, current_year):
        if not os.path.exists(BASE_NVD_FILE_PATH.replace('{year}', str(year))):
            print(f"File for {year} not found")
        else:
            print(BASE_NVD_FILE_PATH.replace('{year}', str(year)))
            with open(BASE_NVD_FILE_PATH.replace('{year}', str(year))) as f:
                nvd_data = json.load(f)
                for entry in nvd_data:
                    cve = entry['cve']['id']
                    print(cve)
                    for version in ["cvssMetricV4", "cvssMetricV31", "cvssMetricV30"]:
                        if version in entry['cve']['metrics']:
                            highest_cvss_data = version
                        else:
                            highest_cvss_data = ''
                    if not highest_cvss_data:
                        continue #skip if no CVSS data
                    cvss_data_gen = (x['cvssData'] for x in entry['cve']['metrics'][highest_cvss_data] if x['type'] == 'Primary')
                    try:
                        cvss_data = next(cvss_data_gen)
                    except StopIteration:
                        cvss_data = {}
                    try:
                        cvss_version = cvss_data['version']
                    except KeyError:
                        cvss_version = ''
                    try:
                        base_score = cvss_data['baseScore']
                    except KeyError:
                        base_score = ''
                    try:
                        base_severity = cvss_data['baseSeverity']
                    except KeyError:
                        base_severity = ''
                    try:
                        base_vector = cvss_data['vectorString']
                    except KeyError:
                        base_vector = ''
                    try:
                        description = ''.join(i['value'] for i in entry['cve']['descriptions'] if i['lang'] == 'en')
                    except KeyError:
                        description = ''

                    new_row = {
                        'cve': cve,
                        'cvss_version': cvss_version,
                        'base_score': base_score,
                        'base_severity': base_severity,
                        'base_vector': base_vector
                    }
                    if not description.startswith('**') and cvss_version: #disputed, rejected, v3.x and up
                        row_accumulator.append(new_row)

    nvd = pd.DataFrame(row_accumulator)
    print ('CVEs from NVD:', nvd['cve'].count())
    return nvd

if __name__ == '__main__':

    nvd_df = process_nvd()
    nvd_df.to_csv('data/nvd.csv', index=False)
