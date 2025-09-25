#!/bin/bash

# CVSS-BT Setup Script
# This script helps new users get started with the CVSS-BT project

set -e  # Exit on any error

echo "🚀 CVSS-BT Setup Script"
echo "======================="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Check if Python 3 is installed
echo "Checking system requirements..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1-2)
    print_status "Python 3 found: $(python3 --version)"
    
    # Check if Python version is 3.8 or higher
    if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)"; then
        print_status "Python version is compatible (3.8+ required)"
    else
        print_error "Python 3.8+ is required. Current version: $PYTHON_VERSION"
        exit 1
    fi
else
    print_error "Python 3 is not installed. Please install Python 3.8+ and try again."
    exit 1
fi

# Check if pip is available
if command -v pip3 &> /dev/null; then
    print_status "pip3 found: $(pip3 --version | cut -d' ' -f1-2)"
else
    print_error "pip3 is not installed. Please install pip3 and try again."
    exit 1
fi

# Check for optional tools
echo
echo "Checking optional tools..."
if command -v curl &> /dev/null; then
    print_status "curl found: $(curl --version | head -n1 | cut -d' ' -f1-2)"
else
    print_warning "curl not found - required for data fetching"
fi

if command -v jq &> /dev/null; then
    print_status "jq found: $(jq --version)"
else
    print_warning "jq not found - required for JSON processing in scripts"
fi

if command -v git &> /dev/null; then
    print_status "git found: $(git --version | cut -d' ' -f1-3)"
else
    print_warning "git not found - required for version control"
fi

# Install Python dependencies
echo
echo "Installing Python dependencies..."
if pip3 install -r code/requirements.txt; then
    print_status "Python dependencies installed successfully"
else
    print_error "Failed to install Python dependencies"
    exit 1
fi

# Verify installation
echo
echo "Verifying installation..."
if python3 -c "import pandas, cvss, ijson, requests; print('All modules imported successfully')" 2>/dev/null; then
    print_status "All Python dependencies verified"
else
    print_error "Dependency verification failed"
    exit 1
fi

# Check for environment variables
echo
echo "Checking configuration..."
if [ -n "$VULNCHECK_API_KEY" ]; then
    print_status "VulnCheck API key found in environment"
else
    print_warning "VulnCheck API key not found in environment variable VULNCHECK_API_KEY"
    echo "  - Sign up at https://vulncheck.com to get an API key"
    echo "  - Set the key with: export VULNCHECK_API_KEY='your_key_here'"
    echo "  - Add to your shell profile (.bashrc, .zshrc, etc.) for persistence"
fi

# Test basic functionality
echo
echo "Testing basic functionality..."
if python3 -c "
import sys
import os
sys.path.append('code')
try:
    # Import individual functions rather than entire modules to avoid execution
    from enrich_nvd import enrich, update_temporal_score, EPSS_THRESHOLD
    print('enrich_nvd functions imported successfully')
except ImportError as e:
    print(f'enrich_nvd import error: {e}')
    sys.exit(1)
except Exception as e:
    print(f'enrich_nvd error: {e}')
    sys.exit(1)

try:
    # Test basic pandas/cvss functionality
    import pandas as pd
    import cvss
    print('Core dependencies working')
except ImportError as e:
    print(f'Dependency error: {e}')
    sys.exit(1)
" 2>/dev/null; then
    print_status "Core modules test passed"
else
    print_error "Core modules test failed"
    exit 1
fi

# Create a simple validation script
echo
echo "Creating validation script..."
cat > validate_setup.py << 'EOF'
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
EOF

chmod +x validate_setup.py
print_status "Validation script created"

# Run validation
echo
echo "Running setup validation..."
if python3 validate_setup.py; then
    print_status "Setup validation passed"
else
    print_warning "Setup validation had warnings (check output above)"
fi

# Final instructions
echo
echo "🎉 Setup Complete!"
echo "=================="
echo
echo "Next steps:"
echo "1. Set VulnCheck API key (if not already set):"
echo "   export VULNCHECK_API_KEY='your_key_here'"
echo
echo "2. Run the validation script anytime:"
echo "   python3 validate_setup.py"
echo
echo "3. Try the full pipeline (requires API key):"
echo "   ./test.sh"
echo
echo "4. Or run basic processing (limited functionality):"
echo "   python3 code/process_nvd.py"
echo
echo "5. Read the full onboarding guide:"
echo "   cat ONBOARDING.md"
echo
echo "6. View existing data:"
echo "   head cvss-bt.csv"
echo
print_status "You're ready to use CVSS-BT! 🚀"