#!/usr/bin/env python3
"""
CVE Search Tool for cvss-bt.csv

This script helps users search and verify CVEs in the cvss-bt.csv file.
It supports case-insensitive search and displays relevant information.

Usage:
    python search_cve.py CVE-2023-44487
    python search_cve.py cve-2023-44487 cve-2022-22719
    python search_cve.py --file custom.csv CVE-2023-44487
"""

import argparse
import csv
import re
import sys
from pathlib import Path


# Constants
MAX_VECTOR_DISPLAY_LENGTH = 80
CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$', re.IGNORECASE)


def validate_cve_id(cve_id):
    """
    Validate CVE ID format.
    
    Args:
        cve_id: CVE ID string to validate
        
    Returns:
        True if valid, False otherwise
    """
    return CVE_PATTERN.match(cve_id.strip()) is not None


def search_cves(csv_file, cve_ids, verbose=False):
    """
    Search for CVEs in the CSV file.
    
    Args:
        csv_file: Path to the CSV file
        cve_ids: List of CVE IDs to search for
        verbose: If True, display full information for each CVE
    
    Returns:
        Dictionary mapping CVE IDs to their data (or None if not found)
    """
    # Validate and normalize CVE IDs
    invalid_cves = []
    for cve in cve_ids:
        if not validate_cve_id(cve):
            invalid_cves.append(cve)
    
    if invalid_cves:
        print(f"Warning: Invalid CVE ID format(s) detected:", file=sys.stderr)
        for cve in invalid_cves:
            print(f"  - {cve} (expected format: CVE-YYYY-NNNNN)", file=sys.stderr)
        print(file=sys.stderr)
    
    normalized_cves = {cve.upper(): cve for cve in cve_ids}
    results = {}
    
    try:
        with open(csv_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                cve = row['cve'].upper()
                if cve in normalized_cves:
                    results[normalized_cves[cve]] = row
                    
        return results
    except FileNotFoundError:
        print(f"Error: File '{csv_file}' not found.", file=sys.stderr)
        print(f"Please ensure you have the cvss-bt.csv file in the current directory.", file=sys.stderr)
        print(f"You can download it from: https://github.com/t0sche/cvss-bt/releases/latest", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading CSV file: {e}", file=sys.stderr)
        sys.exit(1)


def display_results(cve_ids, results, verbose=False):
    """Display search results in a user-friendly format."""
    print(f"\nSearching for {len(cve_ids)} CVE(s)...")
    print("=" * 80)
    
    found_count = 0
    for cve_id in cve_ids:
        if cve_id in results:
            found_count += 1
            data = results[cve_id]
            print(f"\n✓ {cve_id.upper()} - FOUND")
            
            if verbose:
                print(f"  CVSS-BT Score:    {data.get('cvss-bt_score', 'N/A')}")
                print(f"  CVSS-BT Severity: {data.get('cvss-bt_severity', 'N/A')}")
                print(f"  CVSS Version:     {data.get('cvss_version', 'N/A')}")
                print(f"  Base Score:       {data.get('base_score', 'N/A')}")
                print(f"  Base Severity:    {data.get('base_severity', 'N/A')}")
                print(f"  Published Date:   {data.get('published_date', 'N/A')}")
                print(f"  EPSS:             {data.get('epss', 'N/A')}")
                print(f"  CISA KEV:         {data.get('cisa_kev', 'N/A')}")
                print(f"  VulnCheck KEV:    {data.get('vulncheck_kev', 'N/A')}")
                print(f"  ExploitDB:        {data.get('exploitdb', 'N/A')}")
                print(f"  Metasploit:       {data.get('metasploit', 'N/A')}")
                print(f"  Nuclei:           {data.get('nuclei', 'N/A')}")
                print(f"  PoC GitHub:       {data.get('poc_github', 'N/A')}")
                vector = data.get('cvss-bt_vector', 'N/A')
                if len(vector) > MAX_VECTOR_DISPLAY_LENGTH:
                    vector = vector[:MAX_VECTOR_DISPLAY_LENGTH] + "..."
                print(f"  Vector:           {vector}")
            else:
                print(f"  Score: {data.get('cvss-bt_score', 'N/A')} ({data.get('cvss-bt_severity', 'N/A')})")
                print(f"  Published: {data.get('published_date', 'N/A')}")
        else:
            print(f"\n✗ {cve_id.upper()} - NOT FOUND")
    
    print("\n" + "=" * 80)
    print(f"Summary: {found_count} found, {len(cve_ids) - found_count} not found")
    
    return found_count == len(cve_ids)


def main():
    parser = argparse.ArgumentParser(
        description='Search for CVEs in the cvss-bt.csv file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python search_cve.py CVE-2023-44487
  python search_cve.py cve-2023-44487 cve-2022-22719
  python search_cve.py --verbose CVE-2023-44487
  python search_cve.py --file releases/cvss-bt.csv CVE-2023-44487

Note: CVE IDs are case-insensitive. You can use either 'CVE-2023-44487' or 'cve-2023-44487'.
"""
    )
    
    parser.add_argument(
        'cve_ids',
        nargs='+',
        help='One or more CVE IDs to search for (e.g., CVE-2023-44487)'
    )
    
    parser.add_argument(
        '--file',
        default='cvss-bt.csv',
        help='Path to the CSV file (default: cvss-bt.csv)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Display detailed information for each CVE'
    )
    
    args = parser.parse_args()
    
    # Search for CVEs
    results = search_cves(args.file, args.cve_ids, args.verbose)
    
    # Display results
    all_found = display_results(args.cve_ids, results, args.verbose)
    
    # Exit with appropriate code
    sys.exit(0 if all_found else 1)


if __name__ == '__main__':
    main()
