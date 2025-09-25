#!/usr/bin/env python3
"""
CVSS-BT CVE Filtering Example

This script demonstrates how to filter and extract specific CVEs from CVSS-BT data.
"""

import pandas as pd
import sys
import argparse
from datetime import datetime, timedelta

def load_data():
    """Load CVSS-BT data."""
    try:
        df = pd.read_csv('cvss-bt.csv')
        df['published_date'] = pd.to_datetime(df['published_date'])
        return df
    except FileNotFoundError:
        print("✗ cvss-bt.csv not found. Run the processing pipeline first.")
        return None
    except Exception as e:
        print(f"✗ Error loading data: {e}")
        return None

def filter_by_severity(df, severities):
    """Filter CVEs by severity levels."""
    return df[df['cvss-bt_severity'].isin(severities)]

def filter_by_date_range(df, days_back=None, start_date=None, end_date=None):
    """Filter CVEs by date range."""
    if days_back:
        cutoff = datetime.now() - timedelta(days=days_back)
        return df[df['published_date'] >= cutoff]
    
    if start_date:
        start = pd.to_datetime(start_date)
        df = df[df['published_date'] >= start]
    
    if end_date:
        end = pd.to_datetime(end_date)
        df = df[df['published_date'] <= end]
    
    return df

def filter_by_intelligence(df, sources):
    """Filter CVEs by threat intelligence sources."""
    conditions = []
    
    source_mapping = {
        'kev': 'cisa_kev',
        'vulncheck': 'vulncheck_kev',
        'exploitdb': 'exploitdb',
        'metasploit': 'metasploit',
        'nuclei': 'nuclei',
        'github': 'poc_github'
    }
    
    for source in sources:
        if source in source_mapping:
            conditions.append(df[source_mapping[source]] == True)
    
    if conditions:
        # Combine conditions with OR
        combined = conditions[0]
        for condition in conditions[1:]:
            combined = combined | condition
        return df[combined]
    
    return df

def filter_by_epss_threshold(df, threshold):
    """Filter CVEs by EPSS score threshold."""
    return df[df['epss'] >= threshold]

def main():
    """Main filtering function."""
    parser = argparse.ArgumentParser(description='Filter CVSS-BT CVE data')
    
    # Severity filters
    parser.add_argument('--severity', nargs='+', 
                       choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                       help='Filter by severity levels')
    
    # Date filters
    parser.add_argument('--recent', type=int, metavar='DAYS',
                       help='Show CVEs from last N days')
    parser.add_argument('--start-date', type=str,
                       help='Start date (YYYY-MM-DD)')
    parser.add_argument('--end-date', type=str,
                       help='End date (YYYY-MM-DD)')
    
    # Intelligence source filters
    parser.add_argument('--sources', nargs='+',
                       choices=['kev', 'vulncheck', 'exploitdb', 'metasploit', 'nuclei', 'github'],
                       help='Filter by threat intelligence sources')
    
    # EPSS filter
    parser.add_argument('--epss-min', type=float, default=0.0,
                       help='Minimum EPSS score (0.0-1.0)')
    
    # Output options
    parser.add_argument('--limit', type=int, default=100,
                       help='Maximum number of results to show')
    parser.add_argument('--output', type=str,
                       help='Save results to CSV file')
    parser.add_argument('--columns', nargs='+',
                       help='Specific columns to display')
    
    args = parser.parse_args()
    
    print("🔍 CVSS-BT CVE Filter")
    print("=" * 25)
    
    # Load data
    df = load_data()
    if df is None:
        return 1
    
    original_count = len(df)
    print(f"📊 Starting with {original_count:,} CVEs")
    
    # Apply filters
    if args.severity:
        df = filter_by_severity(df, args.severity)
        print(f"   After severity filter ({', '.join(args.severity)}): {len(df):,} CVEs")
    
    if args.recent:
        df = filter_by_date_range(df, days_back=args.recent)
        print(f"   After recent filter (last {args.recent} days): {len(df):,} CVEs")
    elif args.start_date or args.end_date:
        df = filter_by_date_range(df, start_date=args.start_date, end_date=args.end_date)
        print(f"   After date range filter: {len(df):,} CVEs")
    
    if args.sources:
        df = filter_by_intelligence(df, args.sources)
        print(f"   After intelligence filter ({', '.join(args.sources)}): {len(df):,} CVEs")
    
    if args.epss_min > 0:
        df = filter_by_epss_threshold(df, args.epss_min)
        print(f"   After EPSS filter (≥{args.epss_min}): {len(df):,} CVEs")
    
    if len(df) == 0:
        print("❌ No CVEs match the specified criteria")
        return 0
    
    # Sort by CVSS-BT score (descending), handling NaN values
    df = df.sort_values('cvss-bt_score', ascending=False, na_position='last')
    
    # Limit results
    if args.limit and len(df) > args.limit:
        df = df.head(args.limit)
        print(f"   Showing top {args.limit} results")
    
    # Select columns
    if args.columns:
        display_columns = args.columns
    else:
        display_columns = [
            'cve', 'cvss-bt_score', 'cvss-bt_severity', 
            'published_date', 'epss', 'cisa_kev', 'vulncheck_kev'
        ]
    
    # Filter to available columns
    available_columns = [col for col in display_columns if col in df.columns]
    
    print(f"\n🎯 Filtered Results ({len(df):,} CVEs)")
    print("-" * 40)
    
    # Display results
    if len(df) > 0:
        display_df = df[available_columns].head(20)  # Show max 20 rows in terminal
        print(display_df.to_string(index=False, max_rows=20))
        
        if len(df) > 20:
            print(f"\n... and {len(df) - 20} more CVEs")
    
    # Save to file if requested
    if args.output:
        try:
            df[available_columns].to_csv(args.output, index=False)
            print(f"\n💾 Results saved to {args.output}")
        except Exception as e:
            print(f"\n❌ Error saving file: {e}")
    
    print(f"\n✅ Filtering complete!")
    return 0

if __name__ == "__main__":
    sys.exit(main())