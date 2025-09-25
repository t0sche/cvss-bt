# CVSS-BT Quick Start Guide

**Get up and running with CVSS-BT in under 5 minutes!**

## 🚀 One-Command Setup

```bash
# Clone and setup everything automatically
git clone https://github.com/t0sche/cvss-bt.git
cd cvss-bt
./setup.sh
```

## ⚡ Instant Usage

```bash
# Verify everything works
python3 validate_setup.py

# Analyze existing data
python3 examples/analyze_data.py

# Find critical CVEs
python3 examples/filter_cves.py --severity CRITICAL --limit 10
```

## 🎯 Common Tasks

| Task | Command |
|------|---------|
| **View high-priority CVEs** | `python3 examples/filter_cves.py --sources kev --severity CRITICAL` |
| **Recent vulnerabilities** | `python3 examples/filter_cves.py --recent 30` |
| **Export to CSV** | `python3 examples/filter_cves.py --severity HIGH --output results.csv` |
| **Full data analysis** | `python3 examples/analyze_data.py` |

## 📖 Next Steps

- 📚 **Full Guide**: [ONBOARDING.md](ONBOARDING.md)
- 🤝 **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- 💡 **Examples**: [examples/README.md](examples/README.md)

## 🆘 Need Help?

```bash
# Check if everything is working
python3 validate_setup.py

# Get help with filtering options
python3 examples/filter_cves.py --help
```

**That's it! You're ready to use CVSS-BT! 🎉**