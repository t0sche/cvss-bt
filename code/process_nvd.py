from datetime import datetime, date
from pathlib import Path
import pandas as pd
import enrich_nvd
import json
from config_utils import load_config

EPSS_CSV = f'https://epss.cyentia.com/epss_scores-{date.today()}.csv.gz'
TIMESTAMP_FILE = './code/last_run.txt'

# Load configuration
CONFIG = load_config()


def process_nvd_files():
    """
    Processes the NVD JSON files and returns a dataframe.

    Returns:
        nvd_df: A dataframe containing the NVD data.
    """
    nvd_dict = []
    json_files = list(Path('.').glob('*.json'))
    
    if not json_files:
        print("ERROR: No JSON files found in the current directory.")
        print("The script expects NVD JSON files from the unzip operation.")
        print("Check that the download and unzip operations in test.sh completed successfully.")
        print("Creating an empty dataframe to allow processing to continue.")
        return pd.DataFrame(columns=['cve', 'cvss_version', 'base_score', 'base_severity', 
                                    'base_vector', 'assigner', 'published_date', 'description'])

    for file_path in json_files:
        print(f'Processing {file_path.name}')
        try:
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
        except Exception as e:
            print(f"Error processing {file_path.name}: {e}")

    if not nvd_dict:
        print("WARNING: No CVE data was extracted from the JSON files.")
        print("Creating an empty dataframe to allow processing to continue.")
        return pd.DataFrame(columns=['cve', 'cvss_version', 'base_score', 'base_severity', 
                                   'base_vector', 'assigner', 'published_date', 'description'])
    
    nvd_df = pd.DataFrame(nvd_dict)
    print('CVEs with CVSS scores from NVD:', nvd_df['cve'].nunique())

    return nvd_df


def enrich_df(nvd_df):
    """
    Enriches the dataframe with exploit maturity and temporal scores.
    """
    print('Enriching data using custom configuration')
    
    # Check if the dataframe is empty
    if nvd_df.empty:
        print("WARNING: Input dataframe is empty. No enrichment will be performed.")
        print("Creating an empty output file for consistency.")
        # Create empty output file
        pd.DataFrame(columns=[
            'cve', 'cvss-bt_score', 'cvss-bt_severity', 'cvss-bt_vector',
            'weighted_score', 'cvss_version', 'base_score', 'base_severity',
            'base_vector', 'assigner', 'published_date', 'epss',
            'cisa_kev', 'vulncheck_kev', 'exploitdb', 'metasploit', 'nuclei', 'poc_github'
        ]).to_csv('cvss-bt.csv', index=False, mode='w')
        
        # Save configuration info to metadata file
        config_info = {
            'epss_threshold': CONFIG['thresholds']['epss'],
            'high_threshold': CONFIG['scoring']['high_threshold'],
            'functional_threshold': CONFIG['scoring']['functional_threshold'],
            'poc_threshold': CONFIG['scoring']['poc_threshold'],
            'status': 'No CVE data processed'
        }
        with open('cvss-bt-config.json', 'w') as f:
            json.dump(config_info, f, indent=2)
        
        return
    
    # Use appropriate EPSS threshold from configuration
    epss_threshold = CONFIG['thresholds']['epss']
    print(f'Using EPSS threshold: {epss_threshold}')
    
    # Print enabled sources from configuration
    enabled_sources = CONFIG['enabled_sources']
    print('Enabled intelligence sources:')
    for source, enabled in enabled_sources.items():
        print(f'  - {source}: {"Enabled" if enabled else "Disabled"}')
    
    # Print weights for intelligence sources
    weights = CONFIG['weights']
    print('Intelligence source weights:')
    for source, weight in weights.items():
        if enabled_sources.get(source, True):
            print(f'  - {source}: {weight}')
    
    # Load EPSS data
    try:
        epss_df = pd.read_csv(EPSS_CSV, comment='#', compression='gzip')
        print(f'Loaded {len(epss_df)} EPSS scores')
    except Exception as e:
        print(f'Error loading EPSS data: {e}')
        print('Using empty EPSS dataframe')
        epss_df = pd.DataFrame(columns=['cve', 'epss'])
    
    # Enrich data
    enriched_df = enrich_nvd.enrich(nvd_df, epss_df)
    
    # Update temporal score using custom configuration
    cvss_bt_df = enrich_nvd.update_temporal_score(enriched_df)
    
    # Add configuration info to output
    print('Adding configuration metadata to output')
    config_info = {
        'epss_threshold': CONFIG['thresholds']['epss'],
        'high_threshold': CONFIG['scoring']['high_threshold'],
        'functional_threshold': CONFIG['scoring']['functional_threshold'],
        'poc_threshold': CONFIG['scoring']['poc_threshold'],
        'status': 'Processed successfully',
        'cve_count': len(cvss_bt_df)
    }
    
    # Add weighted_score to columns for transparency
    columns = [
        'cve',
        'cvss-bt_score',
        'cvss-bt_severity',
        'cvss-bt_vector',
        'weighted_score',  # Add weighted score for transparency
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
    
    # Ensure all expected columns exist (even if empty)
    for col in columns:
        if col not in cvss_bt_df.columns:
            cvss_bt_df[col] = None
    
    cvss_bt_df = cvss_bt_df[columns]
    cvss_bt_df = cvss_bt_df.sort_values(by=['published_date'])
    cvss_bt_df = cvss_bt_df.reset_index(drop=True)
    
    # Save configuration info to metadata file
    with open('cvss-bt-config.json', 'w') as f:
        json.dump(config_info, f, indent=2)
    
    # Save enriched data
    cvss_bt_df.to_csv('cvss-bt.csv', index=False, mode='w')
    
    print('Data enrichment complete')
    print(f'Processed {len(cvss_bt_df)} CVEs')
    print(f'Configuration used: {config_info}')


def save_last_run_timestamp(filename='last_run.txt'):
    """
    Save the current timestamp as the last run timestamp in a file.

    Args:
        filename (str): The name of the file to save the timestamp. Default is 'last_run.txt'.
    """
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ'))


print('Loading configuration from config.yaml')
print(f'Using configuration: {CONFIG}')
enrich_df(process_nvd_files())
save_last_run_timestamp(TIMESTAMP_FILE)
