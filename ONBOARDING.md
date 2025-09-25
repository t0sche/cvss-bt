# CVSS-BT Onboarding Guide

Welcome to the CVSS-BT (CVSS Base Score + Temporal) project! This guide will help you get started with understanding, using, and contributing to this vulnerability intelligence enrichment system.

## 🎯 Quick Overview

CVSS-BT enriches the National Vulnerability Database (NVD) CVSS scores by adding temporal/threat intelligence metrics. The system automatically processes vulnerability data daily and provides enhanced CVSS scores that consider real-world exploit availability and threat intelligence.

## 📋 Prerequisites

Before getting started, ensure you have:

- **Python 3.8+** installed
- **Git** for version control
- **Curl** and **jq** (for data fetching scripts)
- **VulnCheck API Key** (optional, for full functionality)
- Basic understanding of CVSS scoring and vulnerability management

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/t0sche/cvss-bt.git
cd cvss-bt
```

### 2. Install Dependencies

```bash
pip3 install -r code/requirements.txt
```

### 3. Verify Installation

```bash
python3 -c "import pandas, cvss, ijson; print('All dependencies installed successfully!')"
```

### 4. Download Sample Data (Optional)

To test the system without API keys, you can use the existing `cvss-bt.csv` file:

```bash
head -10 cvss-bt.csv  # View sample output
```

## 🏗️ Project Structure

```
cvss-bt/
├── code/
│   ├── process_nvd.py      # Main processing script
│   ├── enrich_nvd.py       # Enrichment logic with threat intelligence
│   ├── requirements.txt    # Python dependencies
│   └── last_run.txt       # Timestamp of last execution
├── .github/workflows/     # GitHub Actions for automation
├── cvss-bt.csv           # Generated output file
├── test.sh              # Manual testing script
├── README.md            # Project documentation
└── ONBOARDING.md        # This file
```

## 🔧 Configuration

### Environment Variables

For full functionality, set up these environment variables:

```bash
export VULNCHECK_API_KEY="your_vulncheck_api_key_here"
```

### API Keys Required

1. **VulnCheck API Key** (Recommended)
   - Sign up at [vulncheck.com](https://vulncheck.com)
   - Used for enhanced KEV (Known Exploited Vulnerabilities) data
   - Free tier available

## 🎮 Usage

### Running the Full Pipeline

With API key configured:
```bash
./test.sh
```

Without API key (limited functionality):
```bash
pip3 install -r code/requirements.txt
python3 code/process_nvd.py
```

### Understanding the Output

The generated `cvss-bt.csv` contains:

- **cve**: CVE identifier
- **cvss-bt_score**: Enhanced temporal score
- **cvss-bt_severity**: Enhanced severity rating
- **cvss-bt_vector**: CVSS vector with temporal metrics
- **base_score**: Original NVD base score
- **epss**: EPSS probability score
- **cisa_kev**: Boolean - in CISA KEV catalog
- **vulncheck_kev**: Boolean - in VulnCheck KEV
- **exploitdb**: Boolean - has ExploitDB entry
- **metasploit**: Boolean - has Metasploit module
- **nuclei**: Boolean - has Nuclei template
- **poc_github**: Boolean - has GitHub PoC

## 📊 Data Sources

The system enriches CVSS scores using:

1. **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** - Known Exploited Vulnerabilities
2. **[VulnCheck KEV](https://vulncheck.com/kev)** - Extended KEV dataset
3. **[EPSS](https://www.first.org/epss/)** - Exploit Prediction Scoring System
4. **[Metasploit](https://www.metasploit.com/)** - Penetration testing framework
5. **[Nuclei](https://github.com/projectdiscovery/nuclei)** - Vulnerability scanner templates
6. **[ExploitDB](https://www.exploit-db.com/)** - Exploit database
7. **[PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)** - Proof-of-concept exploits

## 🔄 Automation

The project includes GitHub Actions workflows:

- **EPSS Check** (`epss.yml`): Runs daily to check for new EPSS data
- **Enrichment Process** (`cvss-bt.yml`): Processes and publishes updated data

## 🐛 Troubleshooting

### Common Issues

**1. Missing API Key**
```
Error: VulnCheck API key not found
Solution: Set VULNCHECK_API_KEY environment variable
```

**2. Network Connectivity**
```
Error: Failed to fetch data from external sources
Solution: Check internet connection and firewall settings
```

**3. Python Dependencies**
```
Error: Module not found
Solution: pip3 install -r code/requirements.txt
```

**4. Permission Issues**
```
Error: Permission denied
Solution: chmod +x test.sh
```

### Debug Mode

Run with verbose output:
```bash
python3 -u code/process_nvd.py
```

## 🤝 Contributing

### Development Workflow

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature-name`
3. **Make** your changes
4. **Test** thoroughly
5. **Submit** a pull request

### Code Style

- Follow PEP 8 for Python code
- Use meaningful variable names
- Add docstrings for functions
- Include comments for complex logic

### Testing

Before submitting changes:
```bash
# Test basic functionality
python3 -c "import code.process_nvd, code.enrich_nvd"

# Test data processing (requires sample data)
python3 code/process_nvd.py
```

## 📈 Advanced Usage

### Custom EPSS Threshold

Modify the threshold in `code/enrich_nvd.py`:
```python
EPSS_THRESHOLD = 0.36  # Default 36%
```

### Data Filtering

Filter CVEs by date range or severity:
```python
import pandas as pd
df = pd.read_csv('cvss-bt.csv')
high_severity = df[df['cvss-bt_severity'] == 'HIGH']
```

### Integration Examples

**PowerShell (Windows)**
```powershell
$data = Import-Csv -Path "cvss-bt.csv"
$criticalCVEs = $data | Where-Object { $_."cvss-bt_severity" -eq "CRITICAL" }
```

**Python Analysis**
```python
import pandas as pd
df = pd.read_csv('cvss-bt.csv')
kev_cves = df[df['cisa_kev'] == True]
print(f"CVEs in CISA KEV: {len(kev_cves)}")
```

## 📚 Additional Resources

- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
- [CVSS v4.0 Specification](https://www.first.org/cvss/v4-0/cvss-v40-specification.pdf)
- [EPSS Documentation](https://www.first.org/epss/user-guide)
- [VulnCheck API Documentation](https://docs.vulncheck.com/)

## ❓ Support

- **Issues**: [GitHub Issues](https://github.com/t0sche/cvss-bt/issues)
- **Discussions**: [GitHub Discussions](https://github.com/t0sche/cvss-bt/discussions)
- **Email**: Check repository owner's profile

## 🏆 Success Metrics

You've successfully onboarded when you can:

- [ ] Install and run the system locally
- [ ] Understand the output format
- [ ] Explain the temporal scoring methodology
- [ ] Generate updated CVSS-BT data
- [ ] Contribute meaningfully to the project

Welcome to the CVSS-BT community! 🎉