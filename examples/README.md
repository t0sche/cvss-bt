# CVSS-BT Examples

This directory contains example scripts demonstrating how to use and analyze CVSS-BT data.

## Scripts

### 📊 analyze_data.py

Provides comprehensive analysis of the CVSS-BT dataset.

```bash
python3 examples/analyze_data.py
```

**Features:**
- Dataset statistics and summary
- CVSS version distribution
- Severity level breakdown
- Threat intelligence source coverage
- EPSS score analysis
- High-priority CVE identification

### 🔍 filter_cves.py

Command-line tool for filtering and extracting specific CVEs.

```bash
# Show critical/high severity CVEs from last 30 days
python3 examples/filter_cves.py --severity CRITICAL HIGH --recent 30

# Show CVEs in CISA KEV with high EPSS scores
python3 examples/filter_cves.py --sources kev --epss-min 0.5

# Export recent metasploit CVEs to CSV
python3 examples/filter_cves.py --sources metasploit --recent 365 --output recent_metasploit.csv

# Show specific date range with custom columns
python3 examples/filter_cves.py --start-date 2024-01-01 --end-date 2024-12-31 --columns cve cvss-bt_score description
```

**Filter Options:**
- `--severity`: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
- `--recent N`: Show CVEs from last N days
- `--start-date` / `--end-date`: Date range filtering
- `--sources`: Filter by intelligence sources (kev, vulncheck, exploitdb, metasploit, nuclei, github)
- `--epss-min`: Minimum EPSS score threshold
- `--limit`: Maximum number of results
- `--output`: Save to CSV file
- `--columns`: Specify columns to display

## Usage Tips

### Quick Analysis Workflow

1. **Start with overview:**
   ```bash
   python3 examples/analyze_data.py
   ```

2. **Focus on high-priority CVEs:**
   ```bash
   python3 examples/filter_cves.py --severity CRITICAL --sources kev
   ```

3. **Export for further analysis:**
   ```bash
   python3 examples/filter_cves.py --recent 90 --output recent_cves.csv
   ```

### Integration Examples

**PowerShell (Windows):**
```powershell
# Run analysis and capture output
$output = python3 examples/analyze_data.py | Out-String
Write-Host $output
```

**Bash scripting:**
```bash
#!/bin/bash
# Daily security briefing
echo "=== Daily CVE Security Briefing ==="
python3 examples/filter_cves.py --severity CRITICAL HIGH --recent 1 --limit 10
```

**Python integration:**
```python
import subprocess
import pandas as pd

# Run filter and capture CSV output
result = subprocess.run([
    'python3', 'examples/filter_cves.py', 
    '--severity', 'CRITICAL', 
    '--output', 'temp_results.csv'
])

# Load and process results
df = pd.read_csv('temp_results.csv')
# Further analysis...
```

## Custom Analysis

You can use these scripts as templates for custom analysis:

```python
import pandas as pd

# Load CVSS-BT data
df = pd.read_csv('cvss-bt.csv')

# Your custom analysis here
high_risk = df[
    (df['cvss-bt_severity'] == 'CRITICAL') &
    (df['cisa_kev'] == True) &
    (df['epss'] >= 0.5)
]

print(f"Extremely high-risk CVEs: {len(high_risk)}")
```

## Requirements

All examples require the CVSS-BT data file (`cvss-bt.csv`) to be present in the repository root. Generate this file by running the main processing pipeline or use existing data.

Dependencies are automatically installed with the main project:
- pandas
- argparse (built-in)
- datetime (built-in)

## Contributing Examples

Have a useful analysis or filtering scenario? Contribute it:

1. Create a new script in this directory
2. Follow the existing naming pattern
3. Include comprehensive help text and examples
4. Update this README
5. Submit a pull request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for more details.