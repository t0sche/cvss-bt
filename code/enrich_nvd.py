import requests
import os
import re
import pandas as pd
import cvss
from config_utils import load_config, calculate_weighted_score


EPSS_CSV = 'data/epss/epss_scores.csv'
METASPLOIT_JSON = 'https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json'
NUCLEI_JSON = 'https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json'
EXPLOITDB_CSV = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv'
KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
POC_GITHUB = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/README.md"
VULNCHECK_KEV = 'https://api.vulncheck.com/v3/index/vulncheck-kev'
VULNCHECK_API_KEY = os.environ.get('VULNCHECK_API_KEY')

# Load configuration
CONFIG = load_config()

def enrich(df, epss_df):
    """
    Enrich CVE data with EPSS, KEV, ExploitDB, Metasploit, and Nuclei data
    """
    # Check if the dataframe is empty
    if df.empty:
        print("WARNING: Input dataframe is empty. Returning empty enriched dataframe.")
        # Create an empty dataframe with all necessary columns
        empty_df = df.copy()
        empty_df['epss'] = None
        empty_df['cisa_kev'] = False
        empty_df['vulncheck_kev'] = False
        empty_df['exploitdb'] = False
        empty_df['metasploit'] = False
        empty_df['nuclei'] = False
        empty_df['poc_github'] = False
        return empty_df

    # Load enabled sources from config
    enabled_sources = CONFIG['enabled_sources']

    # Load KEV Data if enabled
    if enabled_sources.get('cisa_kev', True):
        print('Loading CISA KEV Data')
        try:
            response = requests.get(KEV_JSON)
            kev_json_data = response.json()
            kev_cve_list = []
            for vuln in kev_json_data.get('vulnerabilities', []):
                kev_cve_list.append(vuln.get('cveID'))
            kev_df = pd.DataFrame(kev_cve_list, columns=['cve'])
            kev_df['cisa_kev'] = True
        except Exception as e:
            print(f"Error loading CISA KEV data: {e}")
            kev_df = pd.DataFrame(columns=['cve'])
            kev_df['cisa_kev'] = False
    else:
        kev_df = pd.DataFrame(columns=['cve'])
        kev_df['cisa_kev'] = False
    
    # Load VulnCheck KEV if enabled
    if enabled_sources.get('vulncheck_kev', True):
        print('Loading VulnCheck KEV Data')
        try:
            vulncheck_kev = get_vulncheck_data()
            vulncheck_kev_df = pd.DataFrame(vulncheck_kev, columns=['cve'])
            vulncheck_kev_df['cve'] = vulncheck_kev_df['cve'].apply(lambda x: ', '.join(map(str, x)))
            vulncheck_kev_df['vulncheck_kev'] = True
        except Exception as e:
            print(f"Error loading VulnCheck KEV data: {e}")
            vulncheck_kev_df = pd.DataFrame(columns=['cve'])
            vulncheck_kev_df['vulncheck_kev'] = False
    else:
        vulncheck_kev_df = pd.DataFrame(columns=['cve'])
        vulncheck_kev_df['vulncheck_kev'] = False

    # Load ExploitDB if enabled
    if enabled_sources.get('exploitdb', True):
        print('Loading ExploitDB Data')
        try:
            exploitdb_df = pd.read_csv(EXPLOITDB_CSV, usecols=['codes']).rename(columns={"codes": "cve"})
            exploitdb_df.drop_duplicates(inplace=True)
            exploitdb_df = exploitdb_df['cve'].str.extract(r"(CVE-\d{4}-\d{4,7})", expand=False).dropna().values
            exploitdb_df = pd.DataFrame(exploitdb_df, columns = ['cve'])
            exploitdb_df['exploitdb'] = True
        except Exception as e:
            print(f"Error loading ExploitDB data: {e}")
            exploitdb_df = pd.DataFrame(columns=['cve'])
            exploitdb_df['exploitdb'] = False
    else:
        exploitdb_df = pd.DataFrame(columns=['cve'])
        exploitdb_df['exploitdb'] = False

    # Load Metasploit if enabled
    if enabled_sources.get('metasploit', True):
        print('Loading Metasploit Data')
        try:
            response = requests.get(METASPLOIT_JSON)
            ms_json_data = response.json()
            ms_cve_list = []
            for item in ms_json_data:
                if 'references' in ms_json_data[item]:
                    cve_references = [ref for ref in ms_json_data[item]['references'] if ref.startswith('CVE-')]
                    ms_cve_list.extend(cve_references)
            metasploit_df = pd.DataFrame(ms_cve_list, columns=['cve'])
            metasploit_df['metasploit'] = True
        except Exception as e:
            print(f"Error loading Metasploit data: {e}")
            metasploit_df = pd.DataFrame(columns=['cve'])
            metasploit_df['metasploit'] = False
    else:
        metasploit_df = pd.DataFrame(columns=['cve'])
        metasploit_df['metasploit'] = False

    # Load Nuclei if enabled
    if enabled_sources.get('nuclei', True):
        print('Loading Nuclei Data')
        try:
            nuclei_df = pd.read_json(NUCLEI_JSON, lines=True)
            nuclei_df.rename(columns={"ID": "cve"}, inplace=True)
            nuclei_df = nuclei_df.drop(columns=['Info', 'file_path'])
            nuclei_df['nuclei'] = True
        except Exception as e:
            print(f"Error loading Nuclei data: {e}")
            nuclei_df = pd.DataFrame(columns=['cve'])
            nuclei_df['nuclei'] = False
    else:
        nuclei_df = pd.DataFrame(columns=['cve'])
        nuclei_df['nuclei'] = False

    # Load Poc-in-GitHub if enabled
    if enabled_sources.get('poc_github', True):
        print('Loading PoC-in-GitHub Data')
        try:
            poc_githib_df = pd.DataFrame(extract_cves_from_github(POC_GITHUB), columns=['cve'])
            poc_githib_df['poc_github'] = True
        except Exception as e:
            print(f"Error loading PoC-in-GitHub data: {e}")
            poc_githib_df = pd.DataFrame(columns=['cve'])
            poc_githib_df['poc_github'] = False
    else:
        poc_githib_df = pd.DataFrame(columns=['cve'])
        poc_githib_df['poc_github'] = False

    # Merge data sources with the main dataframe
    print('Mapping EPSS Data')
    if enabled_sources.get('epss', True) and not epss_df.empty:
        df = pd.merge(df, epss_df, on='cve', how='left')
    else:
        df['epss'] = None

    print('Mapping KEV Data')
    df = pd.merge(df, kev_df, on='cve', how='left')
    
    print('Mapping VulnCheck KEV Data')
    df = pd.merge(df, vulncheck_kev_df, on='cve', how='left')

    print('Mapping ExploitDB Data')
    df = pd.merge(df, exploitdb_df, on='cve', how='left')

    print('Mapping Metasploit Data')
    df = pd.merge(df, metasploit_df, on='cve', how='left')

    print('Mapping Nuclei Data')
    df = pd.merge(df, nuclei_df, on='cve', how='left')

    print('Mapping Poc-in-GitHub Data')
    df = pd.merge(df, poc_githib_df, on='cve', how='left')

    if 'cve' in df.columns:
        df = df.drop_duplicates(subset='cve')
    # Fill NaN values with False
    # With this more type-safe approach:
    # Fill numeric columns with 0 instead of False
    # Handle different column types appropriately
    for col in df.columns:
        if col == 'cve':
            # Skip the cve column
            continue
        elif col == 'epss' or pd.api.types.is_numeric_dtype(df[col]):
            # Fill numeric columns with 0
            df[col] = df[col].fillna(0)
        elif col in ['cisa_kev', 'vulncheck_kev', 'exploitdb', 'metasploit', 'nuclei', 'poc_github']:
            # Convert boolean columns to explicit boolean type before filling
            df[col] = df[col].astype('boolean')
            df[col] = df[col].fillna(False)
        else:
            # For other columns (like strings), fill with empty string
            df[col] = df[col].fillna('')
    
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


def update_temporal_score(df, epss_threshold=None):
    """
    Update temporal score and severity based on exploit maturity
    """
    # Check if the dataframe is empty
    if df.empty:
        print("WARNING: Input dataframe is empty. Returning empty dataframe with default columns.")
        df['exploit_maturity'] = 'E:U'
        df['cvss-bt_vector'] = ''
        df['cvss-bt_score'] = 'UNKNOWN'
        df['cvss-bt_severity'] = 'UNKNOWN'
        df['weighted_score'] = 0.0
        return df
        
    # Load configuration
    config = CONFIG
    
    # Override default EPSS threshold if provided
    if epss_threshold is not None:
        config['thresholds']['epss'] = epss_threshold
    
    # Calculate weighted scores for each vulnerability
    print('Calculating weighted scores based on custom configuration')
    df['weighted_score'] = df.apply(lambda row: calculate_weighted_score(row, config), axis=1)
    
    # Default exploit maturity
    df['exploit_maturity'] = 'E:U'
    
    # Apply custom scoring thresholds from configuration
    high_threshold = config['scoring']['high_threshold']
    functional_threshold = config['scoring']['functional_threshold']
    poc_threshold = config['scoring']['poc_threshold']
    
    # Apply maturity levels based on weighted scores and CVSS version
    # For CVSS 4.0, use 'E:A' for high severity, for others use 'E:H'
    df.loc[(df['weighted_score'] >= high_threshold) & (df['cvss_version'].astype(str) == '4.0'), 'exploit_maturity'] = 'E:A'
    df.loc[(df['weighted_score'] >= high_threshold) & (df['cvss_version'].astype(str) != '4.0'), 'exploit_maturity'] = 'E:H'
    
    # For scores meeting functional threshold but not high threshold
    df.loc[(df['weighted_score'] >= functional_threshold) & 
           (df['weighted_score'] < high_threshold) & 
           (df['cvss_version'].astype(str) != '4.0'), 'exploit_maturity'] = 'E:F'
    
    # For scores meeting PoC threshold but not functional threshold
    df.loc[(df['weighted_score'] >= poc_threshold) & 
           (df['weighted_score'] < functional_threshold) & 
           (df['cvss_version'].astype(str) == '2.0'), 'exploit_maturity'] = 'E:POC'
    
    df.loc[(df['weighted_score'] >= poc_threshold) & 
           (df['weighted_score'] < functional_threshold) & 
           (df['cvss_version'].astype(str) != '2.0') & 
           (df['cvss_version'].astype(str) != '4.0'), 'exploit_maturity'] = 'E:P'
    
    df.loc[(df['weighted_score'] >= poc_threshold) & 
           (df['weighted_score'] < high_threshold) & 
           (df['cvss_version'].astype(str) == '4.0'), 'exploit_maturity'] = 'E:P'

    # Update vector with exploit maturity
    #Remove "E:X" from base vector if it exists
    df['cvss-bt_vector'] = df.apply(lambda row: f"{row['base_vector']}/{row['exploit_maturity']}" if 'E:X' not in row['base_vector'] and row['base_vector'] != 'N/A' \
                                                  else row['base_vector'].replace('/E:X', f"/{row['exploit_maturity']}") if row['base_vector'] != 'N/A' \
                                                  else row['base_vector'], axis=1)

    # Define CVSS computation function
    def compute_cvss(row):
        try:
            if 'N/A' in str(row['cvss_version']):
                return 'UNKNOWN', 'UNKNOWN'
            elif '4' in str(row['cvss_version']):
                c = cvss.CVSS4(row['cvss-bt_vector'])
                return c.base_score, str(c.severity).upper()
            elif '3' in str(row['cvss_version']):
                c = cvss.CVSS3(row['cvss-bt_vector'])
                return c.temporal_score, str(c.severities()[1]).upper()
            elif '2' in str(row['cvss_version']):
                c = cvss.CVSS2(row['cvss-bt_vector'])
                return c.temporal_score, str(c.severities()[1]).upper()
            else:
                raise ValueError(f"Unknown CVSS version: {row['cvss_version']}")
        except Exception as e:
            print(f'Error occurred while computing CVSS: {e}')
            return 'UNKNOWN', 'UNKNOWN'

    # Extracting CVSS scores and severities
    print('Computing CVSS-BT scores and severities')
    df[['cvss-bt_score', 'cvss-bt_severity']] = df.apply(compute_cvss, axis=1, result_type='expand')

    return df
