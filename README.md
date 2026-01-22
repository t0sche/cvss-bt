# cvss-bt
This project enriches the NVD CVSS scores to include Temporal/Threat Metrics, and publishes a CSV file daily with the CVSS-BT scores and information sources.

## Overview

The Common Vulnerability Scoring System (CVSS) is an industry standard for assessing the severity of computer system security vulnerabilities. CVSS attempts to establish a measure of how severe a vulnerability is based on its attributes.

The National Vulnerability Database includes CVSS Base scores in its catalog, but base scores are not enough to effectively prioritizie or contextualize vulnerabilities. In this repository I continuously enrich the CVSS score by using the Exploit Code Maturity/Exploitability (E) Temporal Metric.

### Temporal Metric - Exploit Code Maturity/Exploitability (E)

Sources:
- https://www.first.org/cvss/v4-0/cvss-v40-specification.pdf
- https://www.first.org/cvss/v3.1/specification-document
- https://www.first.org/cvss/v3.0/specification-document
- https://www.first.org/cvss/v2/guide

| Value | Description | CVE Present In |
|---------------------------|-------------|-------------|
| Attacked (A) (v4.0) | Based on available threat intelligence either of the following must apply: Attacks targeting this vulnerability (attempted or successful) have been reported. Solutions to simplify attempts to exploit the vulnerability are publicly or privately available (such as exploit toolkits) | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [VulnCheck KEV](https://vulncheck.com/kev), [EPSS](https://www.first.org/epss/) > Threshold, [Metasploit](https://www.metasploit.com/) |
| High (H) (v3.1/3.0/2.0)| Functional autonomous code exists, or no exploit is required (manual trigger) and details are widely available. Exploit code works in every situation, or is actively being delivered via an autonomous agent (such as a worm or virus). Network-connected systems are likely to encounter scanning or exploitation attempts. Exploit development has reached the level of reliable, widely available, easy-to-use automated tools. | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), [VulnCheck KEV](https://vulncheck.com/kev), [EPSS](https://www.first.org/epss/) > Threshold, [Metasploit](https://www.metasploit.com/) |
| Functional (F) (v3.1/3.0/2.0) | Functional exploit code is available. The code works in most situations where the vulnerability exists. | [Nuclei](https://github.com/projectdiscovery/nuclei) |
| Proof-of-Concept (P) (v4.0/3.1/3.0/2.0) | Proof-of-concept exploit code is available. The code might not work in all situations. | [ExploitDB](https://www.exploit-db.com/), [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) |
| Unproven (U) (v4.0/3.1/3.0/2.0) | No exploit code is available, or an exploit is theoretical. | CVE not present in any threat intelligence source above. |
| Not Defined (X) (v4.0/3.1/3.0/2.0) | Assigning this value to the metric will not influence the score. It means the user does not have enough information to assign a score. | We drop this value since we have information to assign a score. |


## Features
This repository continuously enriches and publishes CVSS Temporal Scores based on the following threat intelligence:

- CISA KEV
- VulnCheck KEV
- EPSS
- Metasploit
- Nuclei
- ExploitDB
- PoC-in-GitHub

### Steps
- Fetches EPSS scores every morning
- Fetches CVSS scores from NVD if there are new EPSS scores.
- Calculates the Exploit Code Maturity/Exploitability (E) Metric when new data is found.
- Provides a resulting CVSS-BT score for each CVE

## Caveats
- In the event that the NVD calculated score is using a lesser version than a secondary source, I use the higher CVSS version.
- The EPSS threshold for returning an `E:H` or `E:A` value is .36, or 36%. This is based on the F1 score of the model and the 37% threshold where most CVEs have weaponized exploit code.
- I do not recommend using this percentage as a general threshold to prioritize on.

## How to Access and Search CVEs

### Downloading the Data

The CVSS-BT data is available in multiple ways:

1. **Latest Release (Recommended)**: Download the latest `cvss-bt.csv` file from the [Releases page](https://github.com/t0sche/cvss-bt/releases/latest)
2. **Repository**: Clone this repository to access the CSV file directly
3. **API**: Use the GitHub Releases API to programmatically access the latest CSV

The CSV file contains over 328,000 CVEs with enriched CVSS scores and temporal metrics.

### Searching for Specific CVEs

#### Using the Included Search Script

This repository includes a Python script to easily search for CVEs:

```bash
# Search for a single CVE (case-insensitive)
python search_cve.py CVE-2023-44487

# Search for multiple CVEs
python search_cve.py CVE-2023-44487 CVE-2023-48795

# Get detailed information
python search_cve.py --verbose CVE-2023-44487

# Search in a custom file
python search_cve.py --file releases/cvss-bt.csv CVE-2023-44487
```

**Note**: CVE IDs are case-insensitive. You can use either `CVE-2023-44487` or `cve-2023-44487`.

#### Using Command Line Tools

You can also search the CSV directly using standard command-line tools:

```bash
# Using grep (case-insensitive search)
grep -i "CVE-2023-44487" cvss-bt.csv

# Search for multiple CVEs
grep -iE "CVE-2023-44487|CVE-2023-48795" cvss-bt.csv

# Count CVEs from a specific year
grep "^CVE-2023" cvss-bt.csv | wc -l
```

#### Using Spreadsheet Applications

Open the CSV file in Excel, Google Sheets, or LibreOffice Calc and use the built-in search and filter features.

#### Using Python/Pandas

```python
import pandas as pd

# Load the CSV
df = pd.read_csv('cvss-bt.csv')

# Search for a specific CVE
cve = df[df['cve'].str.upper() == 'CVE-2023-44487']

# Filter by severity
critical_cves = df[df['cvss-bt_severity'] == 'CRITICAL']

# Filter by EPSS score
high_epss = df[df['epss'] > 0.5]
```

### Data Coverage

- **Total CVEs**: 328,000+ vulnerabilities
- **Date Range**: 1988 - Present
- **Update Frequency**: Daily (when new EPSS data is available)
- **CVSS Versions**: Supports CVSS v2.0, v3.0, v3.1, and v4.0

If you believe a CVE is missing, please:
1. Verify you have the latest release
2. Try the search script with the CVE ID
3. Check if the CVE exists in the [National Vulnerability Database](https://nvd.nist.gov/)
4. Open an issue if the CVE is in NVD but missing from this dataset

## CVSS Visual Mapping
This data visualization provides a breakdown of how the CVSS-B, CVSS-BT and CVSS enriched temporal metrics map to the defined OSINT sources as of November 25th, 2023
![CVSS-BT Mapping](CVSS-BT-Enrichment.png)

## Acknowledgements

This product uses VulnCheck KEV.

This product uses EPSS scores but is not endoresed or certified by the EPSS SIG.

# Support this project
If you'd like to financially support this project, feel free to donate below.

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/stephenshaffer)

