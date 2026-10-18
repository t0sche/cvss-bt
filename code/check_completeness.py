"""
Guard against publishing a CVSS-BT dataset that silently lost CVEs.

Compares the freshly generated CSV against the previously published one and
exits non-zero if the total or any year's CVE count dropped by more than
MAX_DROP, or if a sentinel CVE is missing.

Usage: python code/check_completeness.py <previous.csv> <current.csv>
"""
import sys
import pandas as pd

MAX_DROP = 0.02
"""
Fractional drop allowed before failing. NVD rejections remove a handful of
CVEs per day, nowhere near 2% of a year.
"""

MIN_YEAR_ROWS = 500
"""Years with fewer rows than this in the previous file are too small to compare."""

SENTINEL_CVES = [
    'CVE-2014-0160',
    'CVE-2017-0144',
    'CVE-2021-44228',
    'CVE-2022-22720',
    'CVE-2023-0215',
    'CVE-2023-44487',
    'CVE-2023-48795',
]
"""Well-known CVEs that must always be present (several were missing in issue #30)."""


def load(path):
    df = pd.read_csv(path, usecols=['cve', 'published_date'], dtype=str)
    df['year'] = df['published_date'].str[:4]
    return df


def check(previous, current):
    """
    Return a list of human-readable problems; empty means the dataset looks complete.
    """
    problems = []

    if len(current) < len(previous) * (1 - MAX_DROP):
        problems.append(f'Total rows dropped from {len(previous)} to {len(current)}')

    prev_years = previous['year'].value_counts()
    curr_years = current['year'].value_counts()
    for year, prev_count in prev_years.sort_index().items():
        if prev_count < MIN_YEAR_ROWS:
            continue
        curr_count = int(curr_years.get(year, 0))
        if curr_count < prev_count * (1 - MAX_DROP):
            problems.append(f'{year}: rows dropped from {prev_count} to {curr_count}')

    present = set(current['cve'])
    missing = [cve for cve in SENTINEL_CVES if cve not in present]
    if missing:
        problems.append(f'Sentinel CVEs missing: {", ".join(missing)}')

    return problems


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(f'Usage: {sys.argv[0]} <previous.csv> <current.csv>')

    previous_df = load(sys.argv[1])
    current_df = load(sys.argv[2])
    print(f'Previous: {len(previous_df)} rows, current: {len(current_df)} rows')

    issues = check(previous_df, current_df)
    if issues:
        print('Completeness check FAILED, refusing to publish:')
        for issue in issues:
            print(f'  - {issue}')
        sys.exit(1)
    print('Completeness check passed')
