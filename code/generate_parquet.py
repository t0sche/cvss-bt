#!/usr/bin/env python3
"""
Generate Parquet file from CSV

This script converts the cvss-bt.csv file to a Parquet format for more efficient storage and faster loading.
"""

import pandas as pd
import sys


def csv_to_parquet(csv_file='cvss-bt.csv', parquet_file='cvss-bt.parquet'):
    """
    Convert CSV file to Parquet format.
    
    Args:
        csv_file: Path to input CSV file
        parquet_file: Path to output Parquet file
    """
    print(f"Reading {csv_file}...")
    df = pd.read_csv(csv_file)
    
    print(f"CSV contains {len(df)} rows")
    print(f"Writing to {parquet_file}...")
    
    df.to_parquet(parquet_file, engine='pyarrow', compression='snappy', index=False)
    
    print(f"Successfully created {parquet_file}")


if __name__ == '__main__':
    try:
        csv_to_parquet()
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
