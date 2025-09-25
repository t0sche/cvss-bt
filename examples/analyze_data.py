#!/usr/bin/env python3
"""
CVSS-BT Data Analysis Example

This script demonstrates how to analyze the CVSS-BT enriched vulnerability data.
"""

import pandas as pd
import sys
from datetime import datetime

def main():
    """Main analysis function."""
    print("🔍 CVSS-BT Data Analysis Example")
    print("=" * 40)
    
    # Load the data
    try:
        df = pd.read_csv('cvss-bt.csv')
        print(f"✓ Loaded {len(df)} CVE records")
    except FileNotFoundError:
        print("✗ cvss-bt.csv not found. Run the processing pipeline first.")
        return 1
    except Exception as e:
        print(f"✗ Error loading data: {e}")
        return 1
    
    print("\n📊 Data Summary")
    print("-" * 20)
    
    # Basic statistics
    print(f"Total CVEs: {len(df):,}")
    print(f"Date range: {df['published_date'].min()} to {df['published_date'].max()}")
    
    # CVSS version breakdown
    print(f"\nCVSS Version Distribution:")
    version_counts = df['cvss_version'].value_counts()
    for version, count in version_counts.head().items():
        print(f"  CVSS {version}: {count:,} ({count/len(df)*100:.1f}%)")
    
    # Severity distribution
    print(f"\nCVSS-BT Severity Distribution:")
    severity_counts = df['cvss-bt_severity'].value_counts()
    for severity, count in severity_counts.items():
        if severity != 'UNKNOWN':
            print(f"  {severity}: {count:,} ({count/len(df)*100:.1f}%)")
    
    # Threat intelligence sources
    print(f"\n🎯 Threat Intelligence Coverage")
    print("-" * 30)
    
    intelligence_sources = [
        ('CISA KEV', 'cisa_kev'),
        ('VulnCheck KEV', 'vulncheck_kev'),
        ('ExploitDB', 'exploitdb'),
        ('Metasploit', 'metasploit'),
        ('Nuclei', 'nuclei'),
        ('GitHub PoC', 'poc_github')
    ]
    
    for source_name, column in intelligence_sources:
        count = df[df[column] == True].shape[0]
        print(f"  {source_name}: {count:,} CVEs ({count/len(df)*100:.1f}%)")
    
    # EPSS analysis
    print(f"\n📈 EPSS Score Analysis")
    print("-" * 20)
    epss_mean = df['epss'].mean()
    epss_threshold = 0.36
    high_epss = df[df['epss'] >= epss_threshold].shape[0]
    
    print(f"  Average EPSS score: {epss_mean:.4f}")
    print(f"  CVEs above threshold (≥{epss_threshold}): {high_epss:,} ({high_epss/len(df)*100:.1f}%)")
    
    # High-priority CVEs (multiple criteria)
    print(f"\n🚨 High-Priority CVE Analysis")
    print("-" * 25)
    
    # CVEs with temporal evidence
    temporal_evidence = df[
        (df['cisa_kev'] == True) | 
        (df['vulncheck_kev'] == True) | 
        (df['metasploit'] == True) |
        (df['epss'] >= epss_threshold)
    ]
    
    print(f"  CVEs with exploit evidence: {len(temporal_evidence):,} ({len(temporal_evidence)/len(df)*100:.1f}%)")
    
    # Recent high-severity CVEs
    df['published_date'] = pd.to_datetime(df['published_date'])
    recent_cutoff = pd.Timestamp.now() - pd.Timedelta(days=365)
    recent_critical = df[
        (df['published_date'] >= recent_cutoff) & 
        (df['cvss-bt_severity'] == 'CRITICAL')
    ]
    
    print(f"  Recent critical CVEs (last year): {len(recent_critical):,}")
    
    # Most dangerous combination
    dangerous = df[
        (df['cisa_kev'] == True) & 
        (df['cvss-bt_severity'].isin(['CRITICAL', 'HIGH']))
    ]
    
    print(f"  CISA KEV + Critical/High severity: {len(dangerous):,}")
    
    # Sample high-priority CVEs
    if len(dangerous) > 0:
        print(f"\n🔥 Sample High-Priority CVEs")
        print("-" * 25)
        sample_cols = ['cve', 'cvss-bt_score', 'cvss-bt_severity', 'published_date']
        sample = dangerous.head(5)[sample_cols]
        print(sample.to_string(index=False))
    
    print(f"\n✅ Analysis complete! Use this data to prioritize vulnerability remediation.")
    return 0

if __name__ == "__main__":
    sys.exit(main())