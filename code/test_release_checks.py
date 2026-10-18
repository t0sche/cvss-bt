"""
Tests for the release guards: check_completeness (before publishing) and
check_freshness (after publishing). Uses small synthetic DataFrames and CSVs.
"""
from datetime import datetime, timezone

import pandas as pd

import check_completeness
import check_freshness


def _dataset(rows_per_year, extra_cves=()):
    rows = [{'cve': f'CVE-{year}-{i:05d}', 'published_date': f'{year}-06-01T00:00Z'}
            for year, count in rows_per_year.items() for i in range(count)]
    rows += [{'cve': cve, 'published_date': '2023-01-01T00:00Z'} for cve in extra_cves]
    df = pd.DataFrame(rows)
    df['year'] = df['published_date'].str[:4]
    return df


SENTINELS = check_completeness.SENTINEL_CVES


def test_completeness_passes_on_growth():
    previous = _dataset({'2023': 1000, '2024': 1000}, SENTINELS)
    current = _dataset({'2023': 1000, '2024': 1100}, SENTINELS)
    assert check_completeness.check(previous, current) == []


def test_completeness_flags_year_drop():
    previous = _dataset({'2023': 1000, '2024': 1000}, SENTINELS)
    current = _dataset({'2023': 900, '2024': 1000}, SENTINELS)
    problems = check_completeness.check(previous, current)
    assert any(p.startswith('2023:') for p in problems)


def test_completeness_ignores_small_years():
    # 1999 halves, but it is below MIN_YEAR_ROWS and the total drop stays under MAX_DROP.
    previous = _dataset({'1999': 100, '2023': 5000}, SENTINELS)
    current = _dataset({'1999': 50, '2023': 5000}, SENTINELS)
    assert check_completeness.check(previous, current) == []


def test_completeness_flags_missing_sentinel():
    previous = _dataset({'2023': 1000}, SENTINELS)
    current = _dataset({'2023': 1000}, SENTINELS[1:])
    problems = check_completeness.check(previous, current)
    assert any(SENTINELS[0] in p for p in problems)


def test_freshness_reads_newest_published(tmp_path):
    csv = tmp_path / 'cvss-bt.csv'
    pd.DataFrame({'cve': ['CVE-2026-0001', 'CVE-2026-0002'],
                  'published_date': ['2026-10-01T00:00Z', '2026-10-09T06:08Z']}).to_csv(csv, index=False)
    assert check_freshness.newest_published(csv) == datetime(2026, 10, 9, 6, 8, tzinfo=timezone.utc)


def test_freshness_flags_october_outage():
    newest = datetime(2026, 10, 9, 6, 8, tzinfo=timezone.utc)
    assert not check_freshness.is_stale(newest, datetime(2026, 10, 10, 14, 20, tzinfo=timezone.utc))
    assert check_freshness.is_stale(newest, datetime(2026, 10, 11, 14, 20, tzinfo=timezone.utc))
