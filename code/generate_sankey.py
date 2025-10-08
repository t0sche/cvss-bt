#!/usr/bin/env python3
"""
Generate Sankey diagram showing the flow from CVSS Base Score to Temporal Score to Exploit Availability
"""
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime

# Read the CVSS-BT data
df = pd.read_csv('cvss-bt.csv')

# Convert epss to numeric
df['epss'] = pd.to_numeric(df['epss'], errors='coerce')

# Extract exploit maturity from the vector string
df['exploit_maturity'] = df['cvss-bt_vector'].str.extract(r'E:([A-Z]+)')

# Map exploit maturity to standardized categories
def map_exploit_maturity(row):
    """Map exploit maturity codes to categories"""
    maturity = row['exploit_maturity']
    if maturity == 'A' or maturity == 'H':
        return 'High'
    elif maturity == 'F':
        return 'Functional'
    elif maturity == 'P' or maturity == 'POC':
        return 'Proof-of-Concept'
    else:  # U or None
        return 'Unproven'

df['exploit_category'] = df.apply(map_exploit_maturity, axis=1)

# Define severity ranges for base scores
def get_base_severity_range(score):
    """Categorize base scores into ranges"""
    if pd.isna(score):
        return 'Unknown'
    score = float(score)
    if score == 10:
        return '10'
    elif score >= 9.0:
        return '9-9.9'
    elif score >= 8.0:
        return '8-8.9'
    elif score >= 7.0:
        return '7-7.9'
    elif score >= 6.0:
        return '6-6.9'
    elif score >= 5.0:
        return '5-5.9'
    elif score >= 4.0:
        return '4-4.9'
    elif score >= 3.0:
        return '3-3.9'
    elif score >= 2.0:
        return '2-2.9'
    elif score >= 1.0:
        return '1-1.9'
    else:
        return '0-1.9'

df['base_range'] = df['base_score'].apply(get_base_severity_range)

# Define temporal score ranges
def get_temporal_severity_range(score):
    """Categorize temporal scores into ranges"""
    if pd.isna(score) or score == 'UNKNOWN':
        return 'Unknown'
    try:
        score = float(score)
    except:
        return 'Unknown'
    
    if score == 10:
        return '10'
    elif score >= 9.0:
        return '9-9.9'
    elif score >= 8.0:
        return '8-8.9'
    elif score >= 7.0:
        return '7-7.9'
    elif score >= 6.0:
        return '6-6.9'
    elif score >= 5.0:
        return '5-5.9'
    elif score >= 4.0:
        return '4-4.9'
    elif score >= 3.0:
        return '3-3.9'
    elif score >= 2.0:
        return '2-2.9'
    elif score >= 1.0:
        return '1-1.9'
    else:
        return '0-1.9'

df['temporal_range'] = df['cvss-bt_score'].apply(get_temporal_severity_range)

# Create flows from base score to temporal score
base_to_temporal = df.groupby(['base_range', 'temporal_range']).size().reset_index(name='count')

# Create flows from temporal score to exploit category
temporal_to_exploit = df.groupby(['temporal_range', 'exploit_category']).size().reset_index(name='count')

# Build Sankey diagram data
labels = []
label_to_idx = {}

# Add base score labels
base_ranges = ['0-1.9', '1-1.9', '2-2.9', '3-3.9', '4-4.9', '5-5.9', '6-6.9', '7-7.9', '8-8.9', '9-9.9', '10']
for br in base_ranges:
    if br in base_to_temporal['base_range'].values:
        label = f"{br} ({df[df['base_range'] == br].shape[0]:,})"
        labels.append(label)
        label_to_idx[('base', br)] = len(labels) - 1

# Add temporal score labels
temporal_ranges = ['0-1.9', '1-1.9', '2-2.9', '3-3.9', '4-4.9', '5-5.9', '6-6.9', '7-7.9', '8-8.9', '9-9.9', '10']
for tr in temporal_ranges:
    if tr in temporal_to_exploit['temporal_range'].values:
        label = f"{tr} ({df[df['temporal_range'] == tr].shape[0]:,})"
        labels.append(label)
        label_to_idx[('temporal', tr)] = len(labels) - 1

# Add exploit category labels
exploit_categories = ['High', 'Functional', 'Proof-of-Concept', 'Unproven']
for ec in exploit_categories:
    count = df[df['exploit_category'] == ec].shape[0]
    label = f"{ec} ({count:,})"
    labels.append(label)
    label_to_idx[('exploit', ec)] = len(labels) - 1

# Build source, target, and value lists
sources = []
targets = []
values = []

# Add base to temporal flows
for _, row in base_to_temporal.iterrows():
    if ('base', row['base_range']) in label_to_idx and ('temporal', row['temporal_range']) in label_to_idx:
        sources.append(label_to_idx[('base', row['base_range'])])
        targets.append(label_to_idx[('temporal', row['temporal_range'])])
        values.append(row['count'])

# Add temporal to exploit flows
for _, row in temporal_to_exploit.iterrows():
    if ('temporal', row['temporal_range']) in label_to_idx and ('exploit', row['exploit_category']) in label_to_idx:
        sources.append(label_to_idx[('temporal', row['temporal_range'])])
        targets.append(label_to_idx[('exploit', row['exploit_category'])])
        values.append(row['count'])

# Define colors for the nodes based on severity
colors = []
for label in labels:
    if 'High' in label and '(' in label:
        colors.append('rgba(255, 0, 0, 0.8)')  # Red for High
    elif 'Functional' in label:
        colors.append('rgba(255, 165, 0, 0.8)')  # Orange for Functional
    elif 'Proof-of-Concept' in label:
        colors.append('rgba(255, 255, 0, 0.8)')  # Yellow for Proof-of-Concept
    elif 'Unproven' in label:
        colors.append('rgba(144, 238, 144, 0.8)')  # Light green for Unproven
    elif label.startswith('10 ') or label.startswith('9-9.9'):
        colors.append('rgba(255, 0, 0, 0.6)')  # Red for critical
    elif label.startswith('8-8.9') or label.startswith('7-7.9'):
        colors.append('rgba(255, 165, 0, 0.6)')  # Orange for high
    elif label.startswith('6-6.9') or label.startswith('5-5.9'):
        colors.append('rgba(255, 255, 0, 0.6)')  # Yellow for medium
    else:
        colors.append('rgba(144, 238, 144, 0.6)')  # Green for low

# Create the Sankey diagram
fig = go.Figure(data=[go.Sankey(
    node=dict(
        pad=15,
        thickness=20,
        line=dict(color='black', width=0.5),
        label=labels,
        color=colors
    ),
    link=dict(
        source=sources,
        target=targets,
        value=values
    )
)])

# Update layout
fig.update_layout(
    title={
        'text': f"CVSS Scoring Threat Enrichment<br><sub>https://github.com/t0sche/cvss-bt</sub><br><sub>Generated: {datetime.now().strftime('%Y-%m-%d')}</sub>",
        'x': 0.5,
        'xanchor': 'center',
        'font': {'size': 24}
    },
    font=dict(size=12),
    height=800,
    width=1400
)

# Add annotations for the three columns
fig.add_annotation(
    text="CVSS Base Score",
    xref="paper", yref="paper",
    x=0.05, y=1.05,
    showarrow=False,
    font=dict(size=18, family="Arial Black")
)

fig.add_annotation(
    text="CVSS Temporal Score",
    xref="paper", yref="paper",
    x=0.5, y=1.05,
    showarrow=False,
    font=dict(size=18, family="Arial Black")
)

fig.add_annotation(
    text="Exploit Availability",
    xref="paper", yref="paper",
    x=0.95, y=1.05,
    showarrow=False,
    font=dict(size=18, family="Arial Black")
)

# Add legend information
legend_text = (
    "<b>High</b> = CISA KEV, MetaSploit Module, EPSS> .36<br>"
    "<b>Functional</b> = Nuclei<br>"
    "<b>Proof-of-Concept</b> = ExploitDB<br>"
    "<b>Unproven</b> = None of the Above"
)

fig.add_annotation(
    text=legend_text,
    xref="paper", yref="paper",
    x=0.98, y=0.02,
    xanchor='right',
    showarrow=False,
    font=dict(size=11),
    align='left',
    bgcolor='rgba(255, 255, 255, 0.8)',
    bordercolor='black',
    borderwidth=1
)

# Save the figure
print("Generating Sankey diagram...")
fig.write_image('CVSS-BT-Enrichment.png', width=1400, height=800, scale=2)
print("Sankey diagram saved as CVSS-BT-Enrichment.png")

# Also save as HTML for interactive viewing
fig.write_html('CVSS-BT-Enrichment.html')
print("Interactive version saved as CVSS-BT-Enrichment.html")
