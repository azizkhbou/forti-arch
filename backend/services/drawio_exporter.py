import xml.etree.ElementTree as ET
import html

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
                # Draw.io can parse custom metadata, but for simplicity we encode key properties as an HTML value/tooltip
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
            # Add basic geo layout info for edge
            geom = ET.SubElement(cell, "mxGeometry", {
                "relative": "1",
                "as": "geometry"
            })

        return ET.tostring(mxfile, encoding="utf-8")

    @staticmethod
    def calculate_fallback_layout(nodes):
        """
        Creates a nice Grid/Block layout if coordinates are not supplied.
        - Internet and WAN on top (y: 50-150)
        - FortiGate Central box (y: 200)
        - VDOMs side by side or vertically (y: 350 onwards)
        - Subnets & Servers organized neatly
        """
        coords = {}

        # Position FortiGate
        coords["node_fortigate"] = {"x": 400, "y": 200, "width": 450, "height": 550}
        coords["node_internet"] = {"x": 500, "y": 30, "width": 120, "height": 80}

        vdom_x = 50
        vdom_y = 300

        # Detect VDOMs
        vdom_nodes = [n for n in nodes if n["type"] == "vdom"]

        for idx, v_node in enumerate(vdom_nodes):
            vid = v_node["id"]
            # Position VDOM container
            coords[vid] = {"x": vdom_x + (idx * 380), "y": vdom_y, "width": 350, "height": 400}

            # Position nested child elements within this VDOM
            vdom_name = v_node["details"]["name"]

            # Get zones and items in this vdom
            v_zones = [n for n in nodes if n["type"] == "zone" and n.get("parent") == vid]
            v_intfs = [n for n in nodes if n["type"] == "interface" and (n.get("parent") == vid or n.get("parent") in [z["id"] for z in v_zones])]
            v_vips = [n for n in nodes if n["type"] == "vip" and n.get("parent") == vid]
            v_vpns = [n for n in nodes if n["type"] == "vpn" and n.get("parent") == vid]
            v_subnets = [n for n in nodes if n["type"] == "subnet" and n.get("parent") == vid]
            v_servers = [n for n in nodes if n["type"] == "server" and n.get("parent") == vid]

            # Coordinates are RELATIVE to the parent container in Draw.io
            # Let's stack zones inside VDOM
            zone_y = 50
            for z_idx, zone in enumerate(v_zones):
                coords[zone["id"]] = {"x": 20, "y": zone_y, "width": 310, "height": 100}

                # Position interfaces inside zone
                z_intfs = [i for i in v_intfs if i.get("parent") == zone["id"]]
                for i_idx, intf in enumerate(z_intfs):
                    coords[intf["id"]] = {"x": 15 + (i_idx * 95), "y": 35, "width": 85, "height": 45}

                zone_y += 115

            # Non-zoned interfaces (standalones)
            no_zone_intfs = [i for i in v_intfs if i.get("parent") == vid]
            for i_idx, intf in enumerate(no_zone_intfs):
                coords[intf["id"]] = {"x": 20 + (i_idx * 95), "y": zone_y, "width": 85, "height": 45}

            # Position VIPs and subnets below
            item_y = zone_y + 60
            for idx2, item in enumerate(v_vips + v_vpns + v_subnets + v_servers):
                coords[item["id"]] = {"x": 20 + ((idx2 % 3) * 105), "y": item_y + ((idx2 // 3) * 75), "width": 95, "height": 55}

        # Other loose nodes like remote sites
        remote_nodes = [n for n in nodes if n["type"] == "remote_site"]
        for idx, rn in enumerate(remote_nodes):
            coords[rn["id"]] = {"x": 10 + (idx * 130), "y": 750, "width": 100, "height": 60}

        return coords
