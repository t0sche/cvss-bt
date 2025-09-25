#!/usr/bin/env python3
"""
Simple validation script to verify CVSS-BT setup
"""
import sys
import os
import pandas as pd

def main():
    print("🔍 CVSS-BT Setup Validation")
    print("=" * 30)
    
    # Test imports
    try:
        import cvss
        import ijson
        import requests
        print("✓ All required modules can be imported")
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    
    # Test CVSS-BT specific modules
    try:
        sys.path.append('code')
        from enrich_nvd import enrich, update_temporal_score, EPSS_THRESHOLD
        print("✓ CVSS-BT core functions can be imported")
        print(f"  - EPSS threshold: {EPSS_THRESHOLD}")
    except ImportError as e:
        print(f"✗ CVSS-BT module import error: {e}")
        return False
    except Exception as e:
        print(f"⚠ CVSS-BT module warning: {e}")
    
    # Test CVSS functionality
    try:
        # Test CVSS scoring
        test_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        c = cvss.CVSS3(test_vector)
        print(f"✓ CVSS functionality working (test score: {c.base_score})")
    except Exception as e:
        print(f"✗ CVSS functionality error: {e}")
        return False
    
    # Test CSV reading
    if os.path.exists('cvss-bt.csv'):
        try:
            df = pd.read_csv('cvss-bt.csv')
            print(f"✓ Existing CSV file readable ({len(df)} records)")
            
            # Show sample data
            print("\nSample data:")
            print(df.head(3)[['cve', 'cvss-bt_severity', 'base_score']].to_string())
            
        except Exception as e:
            print(f"✗ Error reading CSV: {e}")
            return False
    else:
        print("ℹ No existing CSV file found (normal for fresh install)")
    
    # Check API key
    if os.getenv('VULNCHECK_API_KEY'):
        print("✓ VulnCheck API key found in environment")
    else:
        print("⚠ VulnCheck API key not set (limited functionality)")
    
    print("\n🎉 Setup validation complete!")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
