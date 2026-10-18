"""
Render the README Sankey: CVSS base severity -> CVSS-BT severity -> exploit maturity.

Flow counts come straight from the published CSV; exploit maturity is read from the
E: metric in cvss-bt_vector, so the chart always matches what the pipeline scored.

Usage: python code/generate_sankey.py [cvss-bt.csv] [CVSS-BT-Enrichment.png]
"""
import sys
from datetime import datetime, timezone

import matplotlib
matplotlib.use('Agg')
import matplotlib.patheffects as pe
import matplotlib.pyplot as plt
from matplotlib.patches import PathPatch, Rectangle
from matplotlib.path import Path
import pandas as pd

SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
MATURITIES = ['Exploited', 'Functional', 'Proof-of-concept', 'Unproven']

E_TO_MATURITY = {
    'A': 'Exploited', 'H': 'Exploited',
    'F': 'Functional',
    'P': 'Proof-of-concept', 'POC': 'Proof-of-concept',
    'U': 'Unproven',
}

# Ordinal one-hue ramps, darkest = most severe; validated with the dataviz ordinal checks.
SEVERITY_COLORS = {'CRITICAL': '#8a1c1c', 'HIGH': '#c4302f', 'MEDIUM': '#e05a58', 'LOW': '#ee968c'}
MATURITY_COLORS = {'Exploited': '#104281', 'Functional': '#256abf', 'Proof-of-concept': '#3987e5', 'Unproven': '#86b6ef'}

SURFACE = '#fcfcfb'
INK = '#0b0b0b'
INK_SECONDARY = '#52514e'

NODE_WIDTH = 0.018
NODE_GAP = 0.025
MIN_NODE_HEIGHT = 0.004
LINK_ALPHA = 0.42
COLUMN_X = [0.17, 0.50, 0.80]
LABEL_SPACING = 0.075
COLUMN_TITLES = ['CVSS Base Severity', 'CVSS-BT Severity', 'Exploit Maturity']


def build_flows(df):
    """
    Return (base->bt counts, bt->maturity counts, excluded row count) for rows with a
    scored severity. Rows with N/A, UNKNOWN or NONE severities are excluded.
    """
    e = df['cvss-bt_vector'].astype(str).str.extract(r'/E:(POC|[AHFPUX])(?=/|$)')[0]
    flows = pd.DataFrame({
        'base': df['base_severity'],
        'bt': df['cvss-bt_severity'],
        'maturity': e.map(E_TO_MATURITY),
    })
    scored = flows['base'].isin(SEVERITIES) & flows['bt'].isin(SEVERITIES) & flows['maturity'].notna()
    flows = flows[scored]
    first = flows.groupby(['base', 'bt']).size()
    second = flows.groupby(['bt', 'maturity']).size()
    return first, second, int((~scored).sum())


def _layout(totals, order):
    """Stack nodes top-down in a fixed order; heights are shares of the unit column."""
    present = [k for k in order if totals.get(k, 0) > 0]
    usable = 1 - NODE_GAP * (len(present) - 1)
    grand = sum(totals[k] for k in present)
    nodes, y = {}, 1.0
    for k in present:
        h = max(usable * totals[k] / grand, MIN_NODE_HEIGHT)
        nodes[k] = (y - h, y)
        y -= h + NODE_GAP
    return nodes


def _band(ax, x0, y0_top, y0_bot, x1, y1_top, y1_bot, color):
    xm = (x0 + x1) / 2
    verts = [(x0, y0_top), (xm, y0_top), (xm, y1_top), (x1, y1_top),
             (x1, y1_bot), (xm, y1_bot), (xm, y0_bot), (x0, y0_bot), (x0, y0_top)]
    codes = [Path.MOVETO, Path.CURVE4, Path.CURVE4, Path.CURVE4,
             Path.LINETO, Path.CURVE4, Path.CURVE4, Path.CURVE4, Path.CLOSEPOLY]
    ax.add_patch(PathPatch(Path(verts, codes), facecolor=color, edgecolor='none', alpha=LINK_ALPHA))


def _draw_links(ax, counts, src_nodes, dst_nodes, src_order, dst_order, x_src, x_dst, color_of):
    """Draw bands sorted by the opposite end's order so flows never cross inside a node."""
    src_total = {k: counts[k].sum() for k in src_nodes}
    dst_total = {k: counts.xs(k, level=1).sum() for k in dst_nodes}
    src_cursor = {k: src_nodes[k][1] for k in src_nodes}
    dst_cursor = {k: dst_nodes[k][1] for k in dst_nodes}
    pairs = [(s, d) for s in src_order for d in dst_order if (s, d) in counts.index]
    # Destination stacking follows source order; source stacking follows destination order.
    dst_offsets = {}
    for d in dst_order:
        for s in src_order:
            if (s, d) in counts.index:
                h = (dst_nodes[d][1] - dst_nodes[d][0]) * counts[(s, d)] / dst_total[d]
                dst_offsets[(s, d)] = (dst_cursor[d], dst_cursor[d] - h)
                dst_cursor[d] -= h
    for s, d in pairs:
        h = (src_nodes[s][1] - src_nodes[s][0]) * counts[(s, d)] / src_total[s]
        top, bot = src_cursor[s], src_cursor[s] - h
        src_cursor[s] = bot
        d_top, d_bot = dst_offsets[(s, d)]
        _band(ax, x_src + NODE_WIDTH / 2, top, bot, x_dst - NODE_WIDTH / 2, d_top, d_bot, color_of(s, d))


def _draw_nodes(ax, nodes, totals, x, colors, label_side, grand):
    label_y = []
    for k, (y0, y1) in nodes.items():
        ax.add_patch(Rectangle((x - NODE_WIDTH / 2, y0), NODE_WIDTH, y1 - y0, facecolor=colors[k], edgecolor=SURFACE, linewidth=1.5))
        label_y.append([k, (y0 + y1) / 2])
    # Nudge labels apart so thin neighbouring nodes stay readable; moved labels get a leader line.
    anchors = [y for _, y in label_y]
    for i in range(1, len(label_y)):
        label_y[i][1] = min(label_y[i][1], label_y[i - 1][1] - LABEL_SPACING)
    halo = [pe.withStroke(linewidth=4, foreground=SURFACE)]
    for (k, y), anchor in zip(label_y, anchors):
        name = k.title() if k in SEVERITIES else k
        share = 100 * totals[k] / grand
        sign = -1 if label_side == 'left' else 1
        edge = x + sign * NODE_WIDTH / 2
        tx = edge + sign * (0.035 if abs(y - anchor) > 1e-9 else 0.008)
        ha = 'right' if label_side == 'left' else 'left'
        if abs(y - anchor) > 1e-9:
            ax.plot([edge, edge + sign * 0.012, tx - sign * 0.004], [anchor, anchor, y], color=INK_SECONDARY, linewidth=0.8)
        ax.text(tx, y + 0.013, name, ha=ha, va='center', fontsize=13, fontweight='bold', color=INK, path_effects=halo)
        ax.text(tx, y - 0.017, f'{totals[k]:,}  ({share:.1f}%)', ha=ha, va='center', fontsize=11,
                color=INK_SECONDARY, path_effects=halo)


def render(df, out_path, as_of=None):
    first, second, excluded = build_flows(df)
    base_totals = first.groupby(level=0).sum().to_dict()
    bt_totals = first.groupby(level=1).sum().to_dict()
    maturity_totals = second.groupby(level=1).sum().to_dict()
    grand = sum(base_totals.values())

    base_nodes = _layout(base_totals, SEVERITIES)
    bt_nodes = _layout(bt_totals, SEVERITIES)
    maturity_nodes = _layout(maturity_totals, MATURITIES)

    fig = plt.figure(figsize=(16, 9), dpi=120, facecolor=SURFACE)
    ax = fig.add_axes([0.02, 0.14, 0.96, 0.70])
    ax.set_xlim(0, 1)
    ax.set_ylim(-0.02, 1.02)
    ax.axis('off')

    _draw_links(ax, first, base_nodes, bt_nodes, SEVERITIES, SEVERITIES, COLUMN_X[0], COLUMN_X[1],
                lambda s, d: SEVERITY_COLORS[s])
    _draw_links(ax, second, bt_nodes, maturity_nodes, SEVERITIES, MATURITIES, COLUMN_X[1], COLUMN_X[2],
                lambda s, d: MATURITY_COLORS[d])

    _draw_nodes(ax, base_nodes, base_totals, COLUMN_X[0], SEVERITY_COLORS, 'left', grand)
    _draw_nodes(ax, bt_nodes, bt_totals, COLUMN_X[1], SEVERITY_COLORS, 'right', grand)
    _draw_nodes(ax, maturity_nodes, maturity_totals, COLUMN_X[2], MATURITY_COLORS, 'right', grand)

    for x, title in zip(COLUMN_X, COLUMN_TITLES):
        ax.text(x, 1.05, title, ha='center', va='bottom', fontsize=15, fontweight='bold', color=INK)

    as_of = as_of or datetime.now(timezone.utc).strftime('%Y-%m-%d')
    fig.text(0.5, 0.955, 'CVSS Scoring Threat Enrichment', ha='center', fontsize=24, fontweight='bold', color=INK)
    fig.text(0.5, 0.915, f'{grand:,} scored CVEs  ·  data as of {as_of}  ·  github.com/t0sche/cvss-bt',
             ha='center', fontsize=12, color=INK_SECONDARY)
    fig.text(0.04, 0.075,
             'Exploited = CISA KEV, VulnCheck KEV or EPSS ≥ 0.36 (plus Metasploit on CVSS 4.0)    '
             'Functional = Metasploit or Nuclei    Proof-of-concept = ExploitDB or PoC-in-GitHub (plus Nuclei on CVSS 4.0)',
             fontsize=10.5, color=INK_SECONDARY)
    fig.text(0.04, 0.045,
             f'Excludes {excluded:,} CVEs without a CVSS score in NVD. Left links are coloured by base severity, '
             'right links by exploit maturity.',
             fontsize=10.5, color=INK_SECONDARY)

    fig.savefig(out_path, facecolor=SURFACE)
    plt.close(fig)
    return first, second, excluded


if __name__ == '__main__':
    csv_path = sys.argv[1] if len(sys.argv) > 1 else 'cvss-bt.csv'
    out = sys.argv[2] if len(sys.argv) > 2 else 'CVSS-BT-Enrichment.png'
    data = pd.read_csv(csv_path, usecols=['base_severity', 'cvss-bt_severity', 'cvss-bt_vector'],
                       keep_default_na=False, dtype=str)
    render(data, out)
    print(f'Wrote {out}')
