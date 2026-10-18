"""
Detect a stale NVD input: fail if the newest CVE in the dataset is too old.

New CVEs are published every day, so a newest published_date more than
MAX_AGE_DAYS behind the run means the upstream NVD backup stopped updating,
even though EPSS changes still make each release look fresh.

Usage: python code/check_freshness.py <current.csv> [as-of ISO timestamp]
"""
import sys
from datetime import datetime, timedelta, timezone
import pandas as pd

MAX_AGE_DAYS = 2
"""Normal runs see a newest CVE under ~1 day old."""


def newest_published(path):
    dates = pd.read_csv(path, usecols=['published_date'])['published_date']
    return pd.to_datetime(dates, utc=True).max().to_pydatetime()


if __name__ == '__main__':
    if len(sys.argv) not in (2, 3):
        sys.exit(f'Usage: {sys.argv[0]} <current.csv> [as-of ISO timestamp]')

    as_of = datetime.fromisoformat(sys.argv[2]) if len(sys.argv) == 3 else datetime.now(timezone.utc)
    newest = newest_published(sys.argv[1])
    age = as_of - newest
    print(f'Newest CVE published {newest:%Y-%m-%dT%H:%MZ}, {age.total_seconds() / 86400:.1f} days before {as_of:%Y-%m-%dT%H:%MZ}')

    if age > timedelta(days=MAX_AGE_DAYS):
        print(f'Freshness check FAILED: NVD input looks stale (older than {MAX_AGE_DAYS} days)')
        sys.exit(1)
    print('Freshness check passed')
