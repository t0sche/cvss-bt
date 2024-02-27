import requests
import os
import re
import pandas as pd
from cvss import CVSS3, CVSS2


EPSS_CSV = 'data/epss/epss_scores.csv'
METASPLOIT_JSON = 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json'
NUCLEI_JSON = 'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json'
EXPLOITDB_CSV = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'
KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
POC_GITHUB = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/README.md"
VULNCHECK_KEV = 'https://api.vulncheck.com/v3/index/vulncheck-kev'
VULNCHECK_API_KEY = os.environ.get('VULNCHECK_API_KEY')

EPSS_THRESHOLD = 0.36
"""
36% is the threshold correlated to the F1 score of EPSSv3 model
At ~37%, the CVE is very likely to have weaponized exploit code
"""

def enrich(df, epss_df):
    """
    Enrich CVE data with EPSS, KEV, ExploitDB, Metasploit, and Nuclei data
    """

    #Load KEV Data
    response = requests.get(KEV_JSON)
    kev_json_data = response.json()
    kev_cve_list = []
    for vuln in kev_json_data.get('vulnerabilities'):
        kev_cve_list.append(vuln.get('cveID'))
    kev_df = pd.DataFrame(kev_cve_list, columns=['cve'])
    kev_df['cisa_kev'] = True
    
    #Load VulnCheck KEV
    vulncheck_kev = get_vulncheck_data()
    vulncheck_kev_df = pd.DataFrame(vulncheck_kev, columns=['cve'])
    vulncheck_kev_df['cve'] = vulncheck_kev_df['cve'].apply(lambda x: ', '.join(map(str, x)))
    vulncheck_kev_df['vulncheck_kev'] = True

    #Load ExploitDB
    exploitdb_df = pd.read_csv(EXPLOITDB_CSV, usecols=['codes']).rename(columns={"codes": "cve"})
    exploitdb_df.drop_duplicates(inplace=True)
    exploitdb_df = exploitdb_df['cve'].str.extract(r"(CVE-\d{4}-\d{4,7})", expand=False).dropna().values
    exploitdb_df = pd.DataFrame(exploitdb_df, columns = ['cve'])
    exploitdb_df['exploitdb'] = True

    #Load Metasploit
    response = requests.get(METASPLOIT_JSON)
    ms_json_data = response.json()
    ms_cve_list = []
    for item in ms_json_data:
        if 'references' in ms_json_data[item]:
            cve_references = [ref for ref in ms_json_data[item]['references'] if ref.startswith('CVE-')]
            ms_cve_list.extend(cve_references)
    metasploit_df = pd.DataFrame(ms_cve_list, columns=['cve'])
    metasploit_df['metasploit'] = True

    #Load Nuclei
    nuclei_df = pd.read_json(NUCLEI_JSON, lines=True)
    nuclei_df.rename(columns={"ID": "cve"}, inplace=True)
    nuclei_df = nuclei_df.drop(columns=['Info', 'file_path'])
    nuclei_df['nuclei'] = True

    #Load Poc-in-GitHub
    poc_githib_df = pd.DataFrame(extract_cves_from_github(POC_GITHUB), columns=['cve'])
    poc_githib_df['poc_github'] = True

    print('Mapping EPSS Data')
    df = pd.merge(df, epss_df, on='cve', how='left').fillna(False)

    print('Mapping KEV Data')
    df = pd.merge(df, kev_df, on='cve', how='left').fillna(False)

    print('Mapping ExploitDB Data')
    df = pd.merge(df, exploitdb_df, on='cve', how='left').fillna(False)

    print('Mapping Metasploit Data')
    df = pd.merge(df, metasploit_df, on='cve', how='left').fillna(False)

    print('Mapping Nuclei Data')
    df = pd.merge(df, nuclei_df, on='cve', how='left').fillna(False)

    print('Mapping Poc-in-GitHub Data')
    df = pd.merge(df, poc_githib_df, on='cve', how='left').fillna(False)

    df = df.drop_duplicates(subset='cve')
    return df


def extract_cves_from_github(url):
    response = requests.get(url)
    if response.status_code == 200:
        content = response.text
    else:
        content = ""
        print("Failed to fetch README file")

    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    cve_matches = re.findall(cve_pattern, content)
    unique_cves = set(cve_matches)
    return list(unique_cves)


def get_vulncheck_data():
    data = []
    headers = {
      "accept": "application/json",
      "authorization": f"Bearer {VULNCHECK_API_KEY}"
    }
    response = requests.get(VULNCHECK_KEV, headers=headers)
    response = response.json()
    current_page = response.get('_meta').get('page')
    total_pages = response.get('_meta').get('total_pages')
    data.extend(response.get('data'))
    while current_page < total_pages:
        current_page += 1
        response = requests.get(f"{VULNCHECK_KEV}?page={current_page}", headers=headers)
        response = response.json()
        data.extend(response.get('data'))
    return data


def update_temporal_score(df, epss_threshold):
    """
    Update temporal score and severity based on exploit maturity
    """
    df['exploit_maturity'] = 'E:U'  # Default value

    # First condition for 'E:H'
    condition_eh = (df['cisa_kev']) | (df['epss'] >= epss_threshold) | (df['vulncheck_kev'])
    # Next condition for 'E:F'
    condition_ef = (~condition_eh) & ((df['nuclei']) | (df['metasploit']))
    # Last condition for 'E:P'
    condition_ep = (~condition_eh) & (~condition_ef) & (df['exploitdb'] | df['poc_github'])

    df.loc[condition_eh, 'exploit_maturity'] = 'E:H'
    df.loc[condition_ef, 'exploit_maturity'] = 'E:F'
    df.loc[condition_ep & (df['cvss_version'].astype(str) == '2.0'), 'exploit_maturity'] = 'E:POC'
    df.loc[condition_ep & (df['cvss_version'].astype(str) != '2.0'), 'exploit_maturity'] = 'E:P'

    # Update vector with exploit maturity
    df['cvss-bt_vector'] = df['base_vector'] + '/' + df['exploit_maturity']

    # Apply CVSS computation
    def compute_cvss(row):
        try:
            if '3' in str(row['cvss_version']):
                c = CVSS3(row['cvss-bt_vector'])
                return c.temporal_score, str(c.severities()[1]).upper()
            elif '2' in str(row['cvss_version']):
                c = CVSS2(row['cvss-bt_vector'])
                return c.temporal_score, str(c.severities()[1]).upper()
            return 'UNKNOWN', 'UNKNOWN'
        except Exception as e:
            print(f'Error occurred while computing CVSS: {e}')
            return 'UNKNOWN', 'UNKNOWN'

    # Extracting CVSS scores and severities
    print('Computing CVSS-BT scores and severities')
    df[['cvss-bt_score', 'cvss-bt_severity']] = df.apply(compute_cvss, axis=1, result_type='expand')

    return df
