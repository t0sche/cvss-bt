"""
Tests for the README Sankey: flow math and rendering on small synthetic data.
"""
import pandas as pd

import generate_sankey

V31 = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
V40 = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'


def _df(rows):
    return pd.DataFrame(rows, columns=['base_severity', 'cvss-bt_severity', 'cvss-bt_vector'])


ROWS = [
    ('CRITICAL', 'CRITICAL', f'{V31}/E:H'),
    ('CRITICAL', 'HIGH', f'{V31}/E:P'),
    ('HIGH', 'MEDIUM', f'{V31}/E:U'),
    # CVSS 4.0 vectors carry E: mid-vector, followed by more metrics.
    ('CRITICAL', 'CRITICAL', f'{V40}/E:A/CR:X/IR:X'),
    ('HIGH', 'HIGH', 'AV:N/AC:L/Au:N/C:C/I:C/A:C/E:POC'),
    ('N/A', 'UNKNOWN', 'N/A'),
    ('NONE', 'NONE', f'{V40}/E:U/CR:X'),
]


def test_flows_map_every_e_value_and_exclude_unscored():
    first, second, excluded = generate_sankey.build_flows(_df(ROWS))
    assert excluded == 2
    assert first.sum() == second.sum() == 5
    assert first[('CRITICAL', 'CRITICAL')] == 2
    assert second[('CRITICAL', 'Exploited')] == 2
    assert second[('HIGH', 'Proof-of-concept')] == 2
    assert second[('MEDIUM', 'Unproven')] == 1


def test_column_totals_are_conserved():
    first, second, _ = generate_sankey.build_flows(_df(ROWS))
    assert first.groupby(level=1).sum().to_dict() == second.groupby(level=0).sum().to_dict()


def test_render_writes_png_with_missing_categories(tmp_path):
    out = tmp_path / 'sankey.png'
    generate_sankey.render(_df(ROWS), out, as_of='2026-01-01')
    assert out.read_bytes()[:8] == b'\x89PNG\r\n\x1a\n'


def test_columns_share_one_scale_when_categories_are_missing():
    first, second, _ = generate_sankey.build_flows(_df(ROWS))
    base = first.groupby(level=0).sum().to_dict()
    bt = first.groupby(level=1).sum().to_dict()
    assert len(base) != len(bt)  # fixture has a category missing in one column
    scales = []
    for totals in (base, bt):
        nodes = generate_sankey._layout(totals, generate_sankey.SEVERITIES)
        scales.append({round((y1 - y0) / totals[k], 9) for k, (y0, y1) in nodes.items()})
    assert scales[0] == scales[1] and len(scales[0]) == 1
