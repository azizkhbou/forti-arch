#!/usr/bin/env python3
"""
Simple FortiGate Network Mapper CLI tool.
Extracts configuration from FortiGate configuration files and prints a simple
architecture containing only VDOMs connected to each other (via routing and policies).
Also generates an interactive single-file HTML architecture page.
"""

import sys
import os
import argparse
from backend.services.topology_builder import TopologyBuilder

def print_simple_architecture(device, simple_topology):
    print("=" * 60)
    print(f" FORTIGATE SIMPLE VDOM ARCHITECTURE MAPPER")
    print("=" * 60)
    print(f"Device: {device.hostname}")
    print(f"Model: {device.model}")
    print(f"OS Version: {device.version}")
    print(f"Serial: {device.serial_number}")
    print("-" * 60)

    # 1. Print detected VDOM nodes
    vdoms = [n for n in simple_topology["nodes"] if n["type"] == "vdom"]
    print(f"Detected {len(vdoms)} VDOMs:")
    for v in vdoms:
        print(f" - {v['label']} ({v['details'].get('mode', 'NAT')})")
    print("-" * 60)

    # 2. Print connections
    edges = simple_topology["edges"]
    print(f"Detected {len(edges)} VDOM Connections:")

    routes = [e for e in edges if e["type"] == "route_link"]
    policies = [e for e in edges if e["type"] == "policy_flow"]

    print("\n[ROUTING]")
    if not routes:
        print("No simple inter-VDOM routes / Internet routes found.")
    else:
        for r in routes:
            src = r["source"].replace("vdom_", "")
            dst = r["target"].replace("vdom_", "").replace("node_internet", "Internet")
            print(f"  {src} ---> {dst} | {r['label']}")

    print("\n[POLICIES]")
    if not policies:
        print("No simple inter-VDOM policies / Internet policies found.")
    else:
        for p in policies:
            src = p["source"].replace("vdom_", "").replace("node_internet", "Internet")
            dst = p["target"].replace("vdom_", "").replace("node_internet", "Internet")
            print(f"  {src} ---> {dst} | {p['label']}")

    print("=" * 60)

def generate_interactive_html(device, simple_topology, output_filename):
    import json
    full_json = json.dumps({
        "device": device.to_dict(),
        "topology": simple_topology
    })

    template = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Simple Architecture - {device.hostname}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.26.0/cytoscape.min.js"></script>
    <style>
        body {{ margin:0; padding:0; font-family:sans-serif; height:100vh; display:flex; flex-direction:column; background-color: #1A202C; color: #E2E8F0; }}
        header {{ background:#2D3748; padding:20px; border-bottom:3px solid #C1272D; display: flex; justify-content: space-between; align-items: center; }}
        h1 {{ margin:0; font-size:1.5rem; color: #FFF; }}
        p {{ margin:5px 0 0; font-size:0.85rem; color:#A0AEC0; }}
        #cy {{ flex:1; background:#111; }}
        .badge {{ background: #C1272D; color: white; padding: 3px 8px; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }}
    </style>
</head>
<body>
    <header>
        <div>
            <h1>Simple FortiGate VDOM Architecture — {device.hostname}</h1>
            <p>Model: {device.model} | Version: {device.version} | Serial: {device.serial_number}</p>
        </div>
        <span class="badge">Ultra-Simple View</span>
    </header>
    <div id="cy"></div>
    <script>
        const data = {full_json};
        const cyElements = [];
        data.topology.nodes.forEach(n => {{
            cyElements.push({{ data: {{ id: n.id, label: n.label, type: n.type, parent: n.parent }} }});
        }});
        data.topology.edges.forEach(e => {{
            cyElements.push({{ data: {{ id: e.id, source: e.source, target: e.target, label: e.label, type: e.type }} }});
        }});

        const cy = cytoscape({{
            container: document.getElementById('cy'),
            elements: cyElements,
            style: [
                {{
                    selector: 'node',
                    style: {{
                        'background-color': '#4A5568',
                        'border-color': '#CBD5E0',
                        'border-width': '2px',
                        'label': 'data(label)',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '14px',
                        'color': '#FFF',
                        'shape': 'round-rectangle',
                        'width': '180px',
                        'height': '70px',
                        'text-wrap': 'wrap'
                    }}
                }},
                {{
                    selector: 'node[type="vdom"]',
                    style: {{
                        'background-color': '#1A365D',
                        'border-color': '#3182CE',
                        'font-weight': 'bold'
                    }}
                }},
                {{
                    selector: 'node[type="internet"]',
                    style: {{
                        'background-color': '#2B6CB0',
                        'border-color': '#63B3ED',
                        'shape': 'ellipse',
                        'width': '120px',
                        'height': '120px',
                        'font-weight': 'bold'
                    }}
                }},
                {{
                    selector: 'edge',
                    style: {{
                        'width': 3,
                        'line-color': '#718096',
                        'target-arrow-color': '#718096',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        'label': 'data(label)',
                        'font-size': '10px',
                        'color': '#FFF',
                        'text-background-opacity': 0.8,
                        'text-background-color': '#2D3748',
                        'text-background-padding': '4px',
                        'text-background-shape': 'round-rectangle'
                    }}
                }},
                {{
                    selector: 'edge[type="route_link"]',
                    style: {{
                        'line-color': '#D69E2E',
                        'target-arrow-color': '#D69E2E',
                        'line-style': 'dashed'
                    }}
                }},
                {{
                    selector: 'edge[type="policy_flow"]',
                    style: {{
                        'line-color': '#38A169',
                        'target-arrow-color': '#38A169'
                    }}
                }}
            ],
            layout: {{
                name: 'circle',
                padding: 100
            }}
        }});

        // Arrange with Internet at the top if present
        const internet = cy.getElementById('node_internet');
        if (internet.length > 0) {{
            // Custom layout
            const vdoms = cy.nodes('[type="vdom"]');
            const numVdoms = vdoms.length;

            internet.position({{ x: 500, y: 150 }});

            const startX = 500 - ((numVdoms - 1) * 300) / 2;
            vdoms.forEach((v, idx) => {{
                v.position({{ x: startX + (idx * 300), y: 400 }});
            }});
            cy.fit();
        }}
    </script>
</body>
</html>"""

    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(template)
    print(f"\n[SUCCESS] Generated simple interactive HTML architecture page at: {output_filename}")

def main():
    parser = argparse.ArgumentParser(description="Extract simple FortiGate configuration and show VDOM connections.")
    parser.add_argument("config_file", help="Path to FortiGate .conf / .txt / .cfg configuration file")
    parser.add_argument("-o", "--output", help="Output interactive HTML filename", default="simple_architecture.html")

    args = parser.parse_args()

    if not os.path.exists(args.config_file):
        print(f"Error: file '{args.config_file}' not found.")
        sys.exit(1)

    with open(args.config_file, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    global_data = {
        "filename": os.path.basename(args.config_file),
        "content": content
    }

    try:
        device, topology, simple_topology = TopologyBuilder.process_configs(global_data)
        print_simple_architecture(device, simple_topology)
        generate_interactive_html(device, simple_topology, args.output)
    except Exception as e:
        print(f"Error during parsing / generating simple architecture: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
