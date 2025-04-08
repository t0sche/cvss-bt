import pandas as pd
import plotly.graph_objects as go
from matplotlib.patches import Polygon, FancyArrowPatch
import matplotlib.pyplot as plt
import numpy as np
import networkx as nx

# Configuration
SHOW_FLOW_COUNTS = True  # Set to False to hide flow counts
FLOW_LABEL_OFFSET = 0.1  # Vertical offset for flow labels
FLOW_CURVE_RADIUS = 0.2  # Curvature radius for arrows
FLOW_WIDTH_SCALE = 1000  # Scale factor for flow width
USE_POLYGON_VIEW = True  # Set to False to use traditional line view
VERTICAL_SPACING = 0.2  # Vertical spacing between flows
HORIZONTAL_SPACING = 0.1  # Horizontal spacing at start/end of flows

# Severity colors and order
severity_colors = {
    'CRITICAL': 'rgba(255, 0, 0, 0.7)',  # Red with 70% opacity
    'HIGH': 'rgba(255, 165, 0, 0.7)',   # Orange with 70% opacity
    'MEDIUM': 'rgba(255, 255, 0, 0.7)', # Yellow with 70% opacity
    'LOW': 'rgba(0, 255, 0, 0.7)'       # Green with 70% opacity
}

# Exploit category colors and order
exploit_category_colors = {
    'High': 'rgba(255, 0, 0, 0.7)',        # Red with 70% opacity
    'Functional': 'rgba(255, 165, 0, 0.7)',  # Orange with 70% opacity
    'Proof-of-concept': 'rgba(255, 255, 0, 0.7)',  # Yellow with 70% opacity
    'Unproven': 'rgba(0, 255, 0, 0.7)'      # Green with 70% opacity
}

# Define the strict order for severities and exploit categories
global_severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
global_exploit_category_order = ['High', 'Functional', 'Proof-of-concept', 'Unproven']

# Count exploit availability categories
def get_exploit_category(row):
    # Convert EPSS value to float if it's a string or boolean
    try:
        epss_value = float(row['epss']) if isinstance(row['epss'], str) else float(row['epss'])
    except (ValueError, TypeError):
        epss_value = 0.0  # Default to 0 if conversion fails
    
    if row['cisa_kev'] or row['metasploit'] or (epss_value >= 0.36):
        return 'High'
    if row['nuclei']:
        return 'Functional'
    if row['exploitdb']:
        return 'Proof-of-concept'
    return 'Unproven'

def convert_rgba_to_rgb(rgba_str):
    """Convert Plotly RGBA string to matplotlib RGB tuple"""
    rgba = rgba_str.strip('rgba()').split(',')
    r, g, b = int(rgba[0]), int(rgba[1]), int(rgba[2])
    return (r/255, g/255, b/255)

def create_bubble_plot_diagram(df, base_severity_counts, cvss_bt_severity_counts, exploit_availability_counts):
    # Create graph
    G = nx.DiGraph()
    
    # Add nodes
    for i, severity in enumerate(global_severity_order):
        if severity in base_severity_counts:
            G.add_node(f'Base {severity}',
                      pos=(0, len(global_severity_order)-i-1),
                      size=base_severity_counts[severity],
                      color=severity_colors[severity])

    for i, severity in enumerate(global_severity_order):
        if severity in cvss_bt_severity_counts:
            G.add_node(f'CVSS-BT {severity}',
                      pos=(1, len(global_severity_order)-i-1),
                      size=cvss_bt_severity_counts[severity],
                      color=severity_colors[severity])

    for i, category in enumerate(global_exploit_category_order):
        if category in exploit_availability_counts:
            G.add_node(f'Exploit {category}',
                      pos=(2, len(global_exploit_category_order)-i-1),
                      size=exploit_availability_counts[category],
                      color=exploit_category_colors[category])

    # Add edges
    base_to_cvss_bt_counts = df.groupby(['base_severity', 'cvss-bt_severity']).size()
    for base_severity in global_severity_order:
        if base_severity in base_severity_counts:
            for cvss_bt_severity in global_severity_order:
                if cvss_bt_severity in cvss_bt_severity_counts:
                    try:
                        flow_value = base_to_cvss_bt_counts[base_severity][cvss_bt_severity]
                    except KeyError:
                        flow_value = 0
                    if flow_value > 0:
                        G.add_edge(f'Base {base_severity}',
                                  f'CVSS-BT {cvss_bt_severity}',
                                  weight=flow_value)

    # Add edges between CVSS-BT severities and exploit categories
    for i, cvss_bt_severity in enumerate(global_severity_order):
        if cvss_bt_severity in cvss_bt_severity_counts:
            severity_rows = df[df['cvss-bt_severity'] == cvss_bt_severity]
            category_counts = severity_rows['exploit_category'].value_counts()
            for j, category in enumerate(global_exploit_category_order):
                if category in category_counts:
                    flow_value = category_counts[category]
                    if flow_value > 0:
                        G.add_edge(f'CVSS-BT {cvss_bt_severity}',
                                  f'Exploit {category}',
                                  weight=flow_value)

    # Create figure
    fig, ax = plt.subplots(figsize=(15, 8))
    
    # Get positions
    pos = nx.get_node_attributes(G, 'pos')
    
    # Get colors
    node_colors = [convert_rgba_to_rgb(G.nodes[n]['color']) for n in G.nodes]
    
    # Draw nodes
    nx.draw_networkx_nodes(G, pos,
                          node_color=node_colors,
                          node_size=[G.nodes[n]['size']/100 for n in G.nodes],
                          ax=ax)
    
    # Draw node labels with counts
    for node in G.nodes:
        node_label = node.split()[1]
        node_count = G.nodes[node]['size']
        ax.text(pos[node][0], pos[node][1],
                f"{node_label}\n({node_count})",
                fontsize=10,
                ha='center',
                va='center',
                color='black')
    
    # Draw edges
    for u, v in G.edges:
        # Calculate edge position
        start_pos = pos[u]
        end_pos = pos[v]
        
        # Determine line color based on the destination node
        if 'Exploit' in v:
            destination_severity = v.split()[1]
            line_color = exploit_category_colors[destination_severity]
        else:
            destination_severity = v.split()[1]
            line_color = severity_colors[destination_severity]
        
        # Draw line
        line = FancyArrowPatch(start_pos, end_pos,
                              connectionstyle="arc3,rad=0",
                              arrowstyle="->",
                              mutation_scale=15,
                              color=convert_rgba_to_rgb(line_color),
                              alpha=0.8,
                              linewidth=G[u][v]['weight']/1000)
        ax.add_patch(line)
        
        # Add count label with matching color
        if SHOW_FLOW_COUNTS:
            label_pos = ((start_pos[0] + end_pos[0])/2, (start_pos[1] + end_pos[1])/2)
            ax.text(label_pos[0], label_pos[1] + FLOW_LABEL_OFFSET,
                    f"{G[u][v]['weight']}",
                    fontsize=8,
                    ha='center',
                    va='center',
                    color=convert_rgba_to_rgb(line_color),
                    bbox=dict(facecolor='white', alpha=0.7, edgecolor='none'))
    
    # Add title and column labels
    ax.set_title('CVSS Scoring Threat Enrichment', fontsize=16)
    ax.text(-0.1, len(global_severity_order)-0.5, 'CVSS Base Score', fontsize=12, ha='center')
    ax.text(1.0, len(global_severity_order)-0.5, 'CVSS Temporal Score', fontsize=12, ha='center')
    ax.text(2.1, len(global_exploit_category_order)-0.5, 'Exploit Availability', fontsize=12, ha='center')
    
    # Add legend
    ax.text(1.5, -0.5, "High = CISA KEV, Metasploit module, EPSS>.36\nFunctional = Nuclei\nProof-of-concept = ExploitDB\nUnproven = None of the above",
            fontsize=10, va='top')
    
    # Set axis limits
    ax.set_xlim(-1, 3)
    ax.set_ylim(-1, max(len(global_severity_order), len(global_exploit_category_order)))
    
    # Remove axes
    ax.axis('off')
    
    # Save the figure
    plt.savefig("cvss-bt-bubble_plot.png", bbox_inches='tight')
    plt.savefig("cvss-bt-bubble_plot.pdf", bbox_inches='tight')
    
    return plt

def create_sankey_diagram(df, base_severity_counts, cvss_bt_severity_counts, exploit_availability_counts):
    # Create unique node labels and colors
    node_labels = []
    node_colors = []
    node_y_positions = []  # Track y-positions for ordering

    # Add base severity nodes
    for i, severity in enumerate(global_severity_order):
        if severity in base_severity_counts:
            node_labels.append(f'Base {severity}')
            node_colors.append(severity_colors[severity])
            node_y_positions.append(len(global_severity_order)-i-1)  # CRITICAL at top (0), LOW at bottom (3)

    # Add CVSS-BT severity nodes
    for i, severity in enumerate(global_severity_order):
        if severity in cvss_bt_severity_counts:
            node_labels.append(f'CVSS-BT {severity}')
            node_colors.append(severity_colors[severity])
            node_y_positions.append(len(global_severity_order)-i-1)  # CRITICAL at top (0), LOW at bottom (3)

    # Add exploit availability nodes
    for i, category in enumerate(global_exploit_category_order):
        if category in exploit_availability_counts:
            node_labels.append(f'Exploit {category}')
            node_colors.append(exploit_category_colors[category])
            node_y_positions.append(len(global_exploit_category_order)-i-1)  # High at top (0), Unproven at bottom (3)

    # Calculate actual flow counts between base and CVSS-BT severities
    base_to_cvss_bt_counts = df.groupby(['base_severity', 'cvss-bt_severity']).size()

    # Create source, target, and value lists for Sankey
    sources = []
    targets = []
    values = []
    link_colors = []  # Store colors for links

    # Add flows between base and CVSS-BT severities
    for base_severity in global_severity_order:
        if base_severity in base_severity_counts:
            for cvss_bt_severity in global_severity_order:
                if cvss_bt_severity in cvss_bt_severity_counts:
                    try:
                        flow_value = base_to_cvss_bt_counts[base_severity][cvss_bt_severity]
                    except KeyError:
                        flow_value = 0
                    if flow_value > 0:
                        sources.append(global_severity_order.index(base_severity))
                        targets.append(len(global_severity_order) + global_severity_order.index(cvss_bt_severity))
                        values.append(flow_value)
                        link_colors.append(severity_colors[cvss_bt_severity])  # Use target node color

    # Add flows between CVSS-BT severities and exploit categories
    for i, cvss_bt_severity in enumerate(global_severity_order):
        if cvss_bt_severity in cvss_bt_severity_counts:
            severity_rows = df[df['cvss-bt_severity'] == cvss_bt_severity]
            category_counts = severity_rows['exploit_category'].value_counts()
            for j, category in enumerate(global_exploit_category_order):
                if category in category_counts:
                    flow_value = category_counts[category]
                    if flow_value > 0:
                        sources.append(len(global_severity_order) + i)
                        targets.append(2 * len(global_severity_order) + j)
                        values.append(flow_value)
                        link_colors.append(exploit_category_colors[category])  # Use target node color

    # Create Sankey figure
    fig = go.Figure(data=[go.Sankey(
        node=dict(
            pad=15,
            thickness=20,
            line=dict(color="black", width=0.5),
            label=node_labels,
            color=node_colors,
            y=node_y_positions  # Explicit y-positions to maintain order
        ),
        link=dict(
            source=sources,
            target=targets,
            value=values,
            color=link_colors  # Use the colors we collected
        )
    )])

    # Add title and column labels
    fig.update_layout(
        title_text="CVSS Scoring Threat Enrichment",
        font=dict(size=14, weight='bold'),
        annotations=[
            # Column labels
            dict(
                x=0.0,
                y=1.0,
                xref='paper',
                yref='paper',
                text="CVSS Base Score",
                showarrow=False,
                font=dict(size=12, weight='bold')
            ),
            dict(
                x=0.5,
                y=1.0,
                xref='paper',
                yref='paper',
                text="CVSS Temporal Score",
                showarrow=False,
                font=dict(size=12, weight='bold')
            ),
            dict(
                x=1.0,
                y=1.0,
                xref='paper',
                yref='paper',
                text="Exploit Availability",
                showarrow=False,
                font=dict(size=12, weight='bold')
            ),
            # Legend below graph
            dict(
                x=1.0,
                y=0.2,
                xref='paper',
                yref='paper',
                text="<b>High</b> = CISA KEV, Metasploit module, EPSS>.36<br><b>Functional</b> = Nuclei<br><b>Proof-of-concept</b> = ExploitDB<br><b>Unproven</b> = None of the above",
                showarrow=False,
                font=dict(size=10)
            )
        ]
    )
    return fig

# Read the CSV file
df = pd.read_csv('cvss-bt.csv')

# Count occurrences of each severity level
base_severity_counts = df['base_severity'].value_counts()
cvss_bt_severity_counts = df['cvss-bt_severity'].value_counts()

# Count exploit availability categories
df['exploit_category'] = df.apply(get_exploit_category, axis=1)
exploit_availability_counts = df['exploit_category'].value_counts()

print("\nBase Severity Counts:")
print(base_severity_counts)
print("\nCVSS-BT Severity Counts:")
print(cvss_bt_severity_counts)
print("\nExploit Category Counts:")
print(exploit_availability_counts)

# Create and show the Sankey diagram
fig = create_sankey_diagram(df, base_severity_counts, cvss_bt_severity_counts, exploit_availability_counts)
fig.show()
fig.write_image("cvss-bt-sankey_diagram.png")
fig.write_image("cvss-bt-sankey_diagram.pdf")

plt = create_bubble_plot_diagram(df, base_severity_counts, cvss_bt_severity_counts, exploit_availability_counts)
plt.show()
