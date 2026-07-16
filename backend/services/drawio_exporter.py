import xml.etree.ElementTree as ET
import html
import re

class DrawioExporter:
    """
    Generates a valid, editable .drawio XML file compatible with diagrams.net.
    Preserves hierarchical grouping (containers) and relative positioning.
    """
    @staticmethod
    def generate_drawio_xml(topology, coordinates=None):
        """
        topology: dict with 'nodes' and 'edges'
        coordinates: dict mapping node_id -> {x, y}
        """
        # Create XML structure
        mxfile = ET.Element("mxfile", {
            "host": "Electron",
            "agent": "FortiGateNetworkMapper",
            "version": "21.0.0",
            "type": "device"
        })
        diagram = ET.SubElement(mxfile, "diagram", {
            "id": "fortigate_layout",
            "name": "Network Topology"
        })
        graph_model = ET.SubElement(diagram, "mxGraphModel", {
            "dx": "1500",
            "dy": "1000",
            "grid": "1",
            "gridSize": "10",
            "guides": "1",
            "tooltips": "1",
            "connect": "1",
            "arrows": "1",
            "fold": "1",
            "page": "1",
            "pageScale": "1",
            "pageWidth": "1654", # A3 Landscape width approx
            "pageHeight": "1169", # A3 Landscape height approx
            "math": "0",
            "shadow": "0"
        })
        root = ET.SubElement(graph_model, "root")

        # Base cells required by Draw.io
        ET.SubElement(root, "mxCell", {"id": "0"})
        ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})

        # Map to find custom positions or use fallback grid layout
        node_coords = coordinates or {}

        # If no coordinates provided, calculate a default hierarchical layout
        if not node_coords:
            node_coords = DrawioExporter.calculate_fallback_layout(topology["nodes"])

        # We first write parent nodes (vdom, zone) so children can refer to them
        containers = [n for n in topology["nodes"] if n["type"] in ["vdom", "zone", "firewall"]]
        leaf_nodes = [n for n in topology["nodes"] if n["type"] not in ["vdom", "zone", "firewall"]]

        # Helper to define styles
        def get_node_style(n_type):
            if n_type == "firewall":
                return "shape=mxgraph.cisco.security.firewall;whiteSpace=wrap;html=1;aspect=fixed;fillColor=#FF0000;strokeColor=#FF0000;align=center;verticalLabelPosition=bottom;verticalAlign=top;"
            elif n_type == "vdom":
                return "swimlane;whiteSpace=wrap;html=1;childLayout=stackLayout;horizontal=1;startSize=30;horizontalStack=0;fillColor=#F8F9FA;strokeColor=#0050EF;strokeWidth=2;fontStyle=1;rounded=1;arcSize=10;"
            elif n_type == "zone":
                return "swimlane;whiteSpace=wrap;html=1;fillColor=#E1F5FE;strokeColor=#03A9F4;strokeWidth=1.5;dashed=1;rounded=1;arcSize=15;"
            elif n_type == "interface":
                return "rounded=1;whiteSpace=wrap;html=1;fillColor=#D5E8D4;strokeColor=#82B366;strokeWidth=1;arcSize=10;"
            elif n_type == "subnet":
                return "shape=cloud;whiteSpace=wrap;html=1;fillColor=#FFF2CC;strokeColor=#D6B656;strokeWidth=1;"
            elif n_type == "internet":
                return "shape=cloud;whiteSpace=wrap;html=1;fillColor=#DAE8FC;strokeColor=#6C8EBF;strokeWidth=2;fontStyle=1;"
            elif n_type == "vpn":
                return "shape=mxgraph.cisco.security.virtual_private_network;whiteSpace=wrap;html=1;aspect=fixed;fillColor=#E3C800;strokeColor=#B09500;"
            elif n_type == "remote_site":
                return "shape=mxgraph.cisco.computers_and_peripherals.workgroup_switch;whiteSpace=wrap;html=1;fillColor=#FFE6CC;strokeColor=#D79B00;"
            elif n_type == "server":
                return "shape=mxgraph.cisco.servers.standard_host;whiteSpace=wrap;html=1;fillColor=#F5F5F5;strokeColor=#666666;"
            elif n_type == "vip":
                return "rhombus;whiteSpace=wrap;html=1;fillColor=#E1D5E7;strokeColor=#B854D4;strokeWidth=1;"
            return "rounded=1;whiteSpace=wrap;html=1;fillColor=#FFFFFF;strokeColor=#000000;"

        # Draw Containers
        for node in containers:
            nid = node["id"]
            ntype = node["type"]
            label = html.escape(node["label"])
            pos = node_coords.get(nid, {"x": 100, "y": 100, "width": 300, "height": 250})

            parent_attr = "1"
            if "parent" in node and node["parent"] in node_coords:
                parent_attr = node["parent"]

            cell_attrs = {
                "id": nid,
                "value": label,
                "style": get_node_style(ntype),
                "parent": parent_attr,
                "vertex": "1"
            }
            cell = ET.SubElement(root, "mxCell", cell_attrs)
            ET.SubElement(cell, "mxGeometry", {
                "x": str(pos.get("x", 100)),
                "y": str(pos.get("y", 100)),
                "width": str(pos.get("width", 300)),
                "height": str(pos.get("height", 250)),
                "as": "geometry"
            })

        # Draw Leaf Nodes
        for node in leaf_nodes:
            nid = node["id"]
            ntype = node["type"]
            label = html.escape(node["label"])
            pos = node_coords.get(nid, {"x": 50, "y": 50, "width": 110, "height": 60})

            parent_attr = "1"
            if "parent" in node:
                # Ensure parent exists in nodes
                p_exists = any(parent_node["id"] == node["parent"] for parent_node in containers)
                if p_exists:
                    parent_attr = node["parent"]

            # Set custom metadata for hover Tooltips in Draw.io if available
            metadata_str = ""
            if "details" in node:
                details = node["details"]
                tooltip_parts = [f"{k}: {v}" for k, v in details.items() if v]
                metadata_str = "\n".join(tooltip_parts)

            cell_attrs = {
                "id": nid,
                "value": label,
                "style": get_node_style(ntype),
                "parent": parent_attr,
                "vertex": "1"
            }
            if metadata_str:
                cell_attrs["tooltip"] = html.escape(metadata_str)

            cell = ET.SubElement(root, "mxCell", cell_attrs)
            ET.SubElement(cell, "mxGeometry", {
                "x": str(pos.get("x", 50)),
                "y": str(pos.get("y", 50)),
                "width": str(pos.get("width", 110)),
                "height": str(pos.get("height", 60)),
                "as": "geometry"
            })

        # Draw Edges (Connections)
        for idx, edge in enumerate(topology["edges"]):
            eid = edge["id"]
            src = edge["source"]
            tgt = edge["target"]
            label = html.escape(edge.get("label", ""))

            # Determine styles: orthogonal, dashed for VPN, etc.
            edge_style = "edgeStyle=orthogonalEdgeStyle;rounded=1;orthogonalLoop=1;jettySize=auto;html=1;strokeWidth=1.5;"
            if edge.get("type") == "vpn_tunnel":
                edge_style += "strokeColor=#B09500;dashed=1;"
            elif edge.get("type") == "wan_link":
                edge_style += "strokeColor=#0050EF;strokeWidth=2;"
            elif edge.get("type") == "policy_flow":
                flow_details = edge.get("details", {})
                action = flow_details.get("action", "accept")
                if action == "deny":
                    edge_style += "strokeColor=#E51400;dashed=1;" # red dashed
                else:
                    edge_style += "strokeColor=#60A917;" # green
            elif edge.get("type") == "subnet_link_deduced":
                edge_style += "strokeColor=#D6B656;dashed=1;"

            cell_attrs = {
                "id": eid,
                "value": label,
                "style": edge_style,
                "parent": "1",
                "source": src,
                "target": tgt,
                "edge": "1"
            }
            cell = ET.SubElement(root, "mxCell", cell_attrs)
            geom = ET.SubElement(cell, "mxGeometry", {
                "relative": "1",
                "as": "geometry"
            })

        return ET.tostring(mxfile, encoding="utf-8")

    @staticmethod
    def calculate_fallback_layout(nodes):
        """
        Creates a structured, non-overlapping layout:
        - Internet is top-center.
        - FortiGate box is next.
        - VDOMs side by side under FortiGate.
        - Interfaces, subnets organized inside columns (Left for LAN, Center for Transit/VPN, Right for DMZ/VIP).
        """
        coords = {}

        # Position FortiGate and Internet
        coords["node_internet"] = {"x": 600, "y": 50, "width": 120, "height": 80}
        coords["node_fortigate"] = {"x": 350, "y": 180, "width": 620, "height": 450}

        # Detect VDOMs
        vdom_nodes = [n for n in nodes if n["type"] == "vdom"]

        vdom_x = 50
        vdom_y = 260

        for idx, v_node in enumerate(vdom_nodes):
            vid = v_node["id"]
            # Position VDOM container
            coords[vid] = {"x": vdom_x + (idx * 480), "y": vdom_y, "width": 450, "height": 380}

            # Position elements inside this VDOM (Relative coordinates to parent)
            # 1. LAN column (Left)
            lan_y = 60
            v_zones = [n for n in nodes if n["type"] == "zone" and n.get("parent") == vid]

            for zone in v_zones:
                z_name = zone["label"].lower()
                if "lan" in z_name or "internal" in z_name or "usr" in z_name:
                    coords[zone["id"]] = {"x": 20, "y": lan_y, "width": 130, "height": 100}

                    # Inside LAN zone
                    z_intfs = [i for i in nodes if i["type"] == "interface" and i.get("parent") == zone["id"]]
                    for i_idx, intf in enumerate(z_intfs):
                        coords[intf["id"]] = {"x": 10, "y": 35 + (i_idx * 45), "width": 110, "height": 40}
                    lan_y += 110

            # Standard LAN interfaces/subnets
            lan_intfs = [i for i in nodes if i["type"] == "interface" and i.get("parent") == vid and ("lan" in i["label"].lower() or "port2" in i["label"].lower())]
            for i in lan_intfs:
                coords[i["id"]] = {"x": 20, "y": lan_y, "width": 110, "height": 40}
                lan_y += 45

            lan_subs = [s for s in nodes if s["type"] == "subnet" and s.get("parent") == vid and ("lan" in s["label"].lower() or "10." in s["label"].lower())]
            for s in lan_subs:
                coords[s["id"]] = {"x": 20, "y": lan_y, "width": 110, "height": 45}
                lan_y += 50

            # 2. DMZ / Servers column (Right)
            dmz_y = 60
            for zone in v_zones:
                z_name = zone["label"].lower()
                if "dmz" in z_name or "srv" in z_name or "server" in z_name:
                    coords[zone["id"]] = {"x": 300, "y": dmz_y, "width": 130, "height": 100}

                    z_intfs = [i for i in nodes if i["type"] == "interface" and i.get("parent") == zone["id"]]
                    for i_idx, intf in enumerate(z_intfs):
                        coords[intf["id"]] = {"x": 10, "y": 35 + (i_idx * 45), "width": 110, "height": 40}
                    dmz_y += 110

            dmz_intfs = [i for i in nodes if i["type"] == "interface" and i.get("parent") == vid and ("dmz" in i["label"].lower() or "port3" in i["label"].lower())]
            for i in dmz_intfs:
                coords[i["id"]] = {"x": 300, "y": dmz_y, "width": 110, "height": 40}
                dmz_y += 45

            vips = [v for v in nodes if v["type"] == "vip" and v.get("parent") == vid]
            for v in vips:
                coords[v["id"]] = {"x": 300, "y": dmz_y, "width": 110, "height": 45}
                dmz_y += 50

            srvs = [s for s in nodes if s["type"] == "server" and s.get("parent") == vid]
            for s in srvs:
                coords[s["id"]] = {"x": 300, "y": dmz_y, "width": 110, "height": 40}
                dmz_y += 45

            # 3. WAN / VPN column (Center)
            wan_y = 60
            wan_intfs = [i for i in nodes if i["type"] == "interface" and i.get("parent") == vid and ("wan" in i["label"].lower() or "port1" in i["label"].lower() or "vlink" in i["label"].lower())]
            for i in wan_intfs:
                coords[i["id"]] = {"x": 160, "y": wan_y, "width": 120, "height": 40}
                wan_y += 45

            vpns = [v for v in nodes if v["type"] == "vpn" and v.get("parent") == vid]
            for v in vpns:
                coords[v["id"]] = {"x": 160, "y": wan_y, "width": 110, "height": 45}
                wan_y += 50

            any_subs = [s for s in nodes if s["type"] == "subnet" and s.get("parent") == vid and ("any" in s["label"].lower() or "0.0.0.0" in s["label"].lower())]
            for s in any_subs:
                coords[s["id"]] = {"x": 160, "y": wan_y, "width": 110, "height": 45}
                wan_y += 50

        # Position remote sites at the bottom edges
        remote_nodes = [n for n in nodes if n["type"] == "remote_site"]
        for idx, rn in enumerate(remote_nodes):
            coords[rn["id"]] = {"x": 100 + (idx * 800), "y": 680, "width": 110, "height": 60}

        return coords
