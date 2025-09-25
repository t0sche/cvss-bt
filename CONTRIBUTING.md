# Contributing to CVSS-BT

Thank you for your interest in contributing to CVSS-BT! This document provides guidelines and information for contributors.

## 🌟 How to Contribute

### Types of Contributions

We welcome various types of contributions:

- **Bug Reports** - Help us identify and fix issues
- **Feature Requests** - Suggest new functionality or improvements
- **Code Contributions** - Fix bugs, add features, or improve performance
- **Documentation** - Improve guides, comments, or examples
- **Data Sources** - Suggest new threat intelligence sources
- **Testing** - Help test new features or edge cases

## 🚀 Getting Started

### 1. Development Setup

Follow the [ONBOARDING.md](ONBOARDING.md) guide to set up your development environment.

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/cvss-bt.git
cd cvss-bt

# Run setup script
./setup.sh

# Verify setup
python3 validate_setup.py
```

### 2. Understanding the Codebase

Key files and their purposes:

- `code/process_nvd.py` - Main processing logic for NVD data
- `code/enrich_nvd.py` - Threat intelligence enrichment logic
- `test.sh` - Integration test script
- `.github/workflows/` - Automated workflows

### 3. Development Workflow

1. **Create an Issue** (for significant changes)
2. **Fork the Repository**
3. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```
4. **Make Your Changes**
5. **Test Thoroughly**
6. **Commit with Clear Messages**
7. **Push to Your Fork**
8. **Create a Pull Request**

## 🧪 Testing Guidelines

### Before Submitting Changes

1. **Run Basic Tests**
   ```bash
   python3 validate_setup.py
   ```

2. **Test Import Functionality**
   ```bash
   python3 -c "import code.process_nvd, code.enrich_nvd; print('Imports successful')"
   ```

3. **Test with Sample Data** (if available)
   ```bash
   # This requires existing JSON files or mock data
   python3 code/process_nvd.py
   ```

4. **Validate Output Format**
   ```bash
   # Verify CSV structure
   head -5 cvss-bt.csv
   ```

### Integration Testing

If you have a VulnCheck API key, test the full pipeline:
```bash
export VULNCHECK_API_KEY="your_key"
./test.sh
```

## 📝 Code Style Guidelines

### Python Code Style

- Follow [PEP 8](https://pep8.org/) style guidelines
- Use meaningful variable and function names
- Add docstrings for all functions and classes
- Include type hints where appropriate

Example:
```python
def process_vulnerability_data(cve_id: str, cvss_vector: str) -> dict:
    """
    Process individual vulnerability data and return enriched information.
    
    Args:
        cve_id: CVE identifier (e.g., 'CVE-2023-12345')
        cvss_vector: CVSS vector string
        
    Returns:
        Dictionary containing processed vulnerability data
    """
    # Implementation here
    pass
```

### Commit Message Format

Use clear, descriptive commit messages:

```
type(scope): brief description

Longer description if needed
- List specific changes
- Reference issues: Fixes #123
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

Examples:
- `feat(enrichment): add support for CVSS v4.0 temporal metrics`
- `fix(processing): handle missing EPSS data gracefully`
- `docs(onboarding): add troubleshooting section`

## 🔧 Common Development Tasks

### Adding a New Data Source

1. **Research the API/Data Format**
2. **Add Constants** to `enrich_nvd.py`:
   ```python
   NEW_SOURCE_URL = 'https://api.example.com/vulnerabilities'
   ```

3. **Create Fetching Function**:
   ```python
   def fetch_new_source_data():
       """Fetch data from new source."""
       response = requests.get(NEW_SOURCE_URL)
       return response.json()
   ```

4. **Integrate into Enrichment Logic**:
   ```python
   # In enrich() function
   new_source_data = fetch_new_source_data()
   # Process and merge with existing data
   ```

5. **Update Documentation** and tests

### Modifying CVSS Scoring Logic

1. **Understand Current Logic** in `update_temporal_score()`
2. **Test Changes** with known CVEs
3. **Validate Score Ranges** (0-10 for most CVSS versions)
4. **Update Documentation** if scoring methodology changes

### Performance Improvements

1. **Profile Current Performance**:
   ```python
   import cProfile
   cProfile.run('your_function()')
   ```

2. **Optimize Data Processing**:
   - Use pandas vectorization
   - Implement chunked processing for large datasets
   - Add progress indicators for long operations

3. **Memory Management**:
   - Process data in batches
   - Clean up temporary variables
   - Use generators for large datasets

## 🐛 Bug Reports

### Before Reporting

1. **Search Existing Issues** to avoid duplicates
2. **Test with Latest Version**
3. **Gather Debug Information**

### Bug Report Template

```markdown
## Bug Description
Brief description of the issue

## Steps to Reproduce
1. Step one
2. Step two
3. Expected vs actual behavior

## Environment
- OS: [e.g., Ubuntu 20.04]
- Python Version: [e.g., 3.9.7]
- CVSS-BT Version: [e.g., commit hash]

## Error Messages
```
Paste any error messages or logs here
```

## Additional Context
Any other relevant information
```

## 💡 Feature Requests

### Feature Request Template

```markdown
## Feature Description
Clear description of the proposed feature

## Use Case
Why is this feature needed? What problem does it solve?

## Proposed Solution
How should this feature work?

## Alternatives Considered
Other approaches you've thought about

## Additional Context
Any other relevant information or examples
```

## 🔍 Code Review Process

### For Contributors

- **Self-Review**: Review your own code before submitting
- **Test Coverage**: Ensure changes are tested
- **Documentation**: Update docs for any user-facing changes
- **Breaking Changes**: Clearly mark and explain breaking changes

### Review Criteria

We evaluate contributions based on:

- **Functionality**: Does it work as intended?
- **Code Quality**: Is it readable and maintainable?
- **Performance**: Does it introduce performance issues?
- **Security**: Are there any security implications?
- **Compatibility**: Does it break existing functionality?

## 📚 Resources

### Helpful Links

- [CVSS Specification Documents](https://www.first.org/cvss/)
- [Pandas Documentation](https://pandas.pydata.org/docs/)
- [Python CVS Library](https://pypi.org/project/cvss/)
- [VulnCheck API Docs](https://docs.vulncheck.com/)

### Learning Resources

- [Understanding CVSS](https://www.first.org/cvss/user-guide)
- [Threat Intelligence Basics](https://www.sans.org/white-papers/threat-intelligence/)
- [Python for Data Science](https://pandas.pydata.org/pandas-docs/stable/getting_started/intro_tutorials/)

## 🤝 Community Guidelines

### Be Respectful

- Use welcoming and inclusive language
- Respect differing viewpoints and experiences
- Give and receive constructive feedback gracefully

### Be Collaborative

- Help newcomers get started
- Share knowledge and resources
- Credit others for their contributions

### Be Professional

- Focus on what is best for the community
- Show empathy towards other community members
- Be patient with questions and learning

## 📞 Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Code Comments**: For specific implementation questions

## 🏆 Recognition

Contributors are recognized through:

- **GitHub Contributors** section
- **Release Notes** acknowledgments
- **Special Thanks** in documentation

Thank you for contributing to CVSS-BT! Your efforts help make vulnerability management better for everyone. 🎉