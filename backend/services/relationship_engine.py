import re

class RelationshipEngine:
    """
    Builds topological links and identifies relationships:
    - Interface to Zone membership
    - VPN to external Gateways
    - Inter-VDOM connections
    - VIP targets
    - Inferred mappings using IP longest prefix matches
    """
    @staticmethod
    def build_relationships(device):
        topology = {
            "nodes": [],
            "edges": []
        }

        # 1. Global / Internet Node
        topology["nodes"].append({
            "id": "node_internet",
            "label": "Internet",
            "type": "internet",
            "vdom": "global",
            "details": {"description": "Réseau public mondial / WAN"}
        })

        # 2. Main FortiGate Box Node
        topology["nodes"].append({
            "id": "node_fortigate",
            "label": f"FortiGate: {device.hostname}",
            "type": "firewall",
            "vdom": "global",
            "details": {
                "hostname": device.hostname,
                "model": device.model,
                "version": device.version,
                "serial": device.serial_number
            }
        })

        # Track VDOM nodes
        for vdom_name, vdom in device.vdoms.items():
            vdom_node_id = f"vdom_{vdom_name}"
            topology["nodes"].append({
                "id": vdom_node_id,
                "label": f"VDOM: {vdom_name}",
                "type": "vdom",
                "parent": "node_fortigate",
                "details": {"mode": vdom.mode, "name": vdom_name}
            })

            # Sub-track for Zones
            for zone_name, zone in vdom.zones.items():
                zone_node_id = f"zone_{vdom_name}_{zone_name}"
                topology["nodes"].append({
                    "id": zone_node_id,
                    "label": f"Zone: {zone_name}",
                    "type": "zone",
                    "parent": vdom_node_id,
                    "details": {
                        "name": zone_name,
                        "intrazone": zone.intrazone,
                        "interfaces": zone.interfaces,
                        "role": zone.role
                    }
                })

            # Sub-track for Interfaces
            for intf_name, intf in vdom.interfaces.items():
                intf_node_id = f"intf_{vdom_name}_{intf_name.replace('/', '_').replace('.', '_')}"

                # Determine parent container: Zone if assigned, otherwise VDOM
                parent_id = vdom_node_id
                if intf.zone and intf.zone in vdom.zones:
                    parent_id = f"zone_{vdom_name}_{intf.zone}"
                elif not intf.zone:
                    # check if system zone defines it
                    found_zone = None
                    for z_name, z in vdom.zones.items():
                        if intf_name in z.interfaces:
                            found_zone = z_name
                            intf.zone = z_name
                            break
                    if found_zone:
                        parent_id = f"zone_{vdom_name}_{found_zone}"

                # Define role & type colors/tags
                topology["nodes"].append({
                    "id": intf_node_id,
                    "label": f"{intf_name}\n{intf.ip}/{intf.mask}" if intf.ip != "0.0.0.0" else intf_name,
                    "type": "interface",
                    "parent": parent_id,
                    "details": {
                        "name": intf_name,
                        "alias": intf.alias,
                        "ip": intf.ip,
                        "mask": intf.mask,
                        "role": intf.role,
                        "type": intf.type,
                        "vlan_id": intf.vlan_id,
                        "status": intf.status,
                        "admin_access": intf.admin_access,
                        "dhcp": intf.dhcp_mode,
                        "vdom": vdom_name
                    }
                })

                # If interface has WAN role or parent suggests WAN, link it to Internet
                if intf.role.lower() == "wan" or "wan" in intf_name.lower() or "internet" in intf_name.lower():
                    topology["edges"].append({
                        "id": f"edge_wan_{intf_node_id}",
                        "source": intf_node_id,
                        "target": "node_internet",
                        "label": "Accès WAN",
                        "type": "wan_link"
                    })

            # Sub-track for VIPs
            for vip_name, vip in vdom.vips.items():
                vip_node_id = f"vip_{vdom_name}_{vip_name.replace(' ', '_')}"

                # Find appropriate parent vdom
                topology["nodes"].append({
                    "id": vip_node_id,
                    "label": f"VIP: {vip_name}\nExt: {vip.extip}\nInt: {vip.mappedip}",
                    "type": "vip",
                    "parent": vdom_node_id,
                    "details": {
                        "name": vip_name,
                        "extip": vip.extip,
                        "mappedip": vip.mappedip,
                        "portforward": vip.portforward,
                        "extport": vip.extport,
                        "mappedport": vip.mappedport,
                        "vdom": vdom_name
                    }
                })

                # Link VIP to external interface if set
                if vip.extintf != "any":
                    ext_intf_id = f"intf_{vdom_name}_{vip.extintf.replace('/', '_').replace('.', '_')}"
                    topology["edges"].append({
                        "id": f"edge_vip_ext_{vip_node_id}",
                        "source": ext_intf_id,
                        "target": vip_node_id,
                        "label": "Publication",
                        "type": "vip_link"
                    })
                else:
                    # Link to internet directly or any WAN interface
                    topology["edges"].append({
                        "id": f"edge_vip_internet_{vip_node_id}",
                        "source": "node_internet",
                        "target": vip_node_id,
                        "label": "Publication",
                        "type": "vip_link"
                    })

                # Create inferred internal server or link to internal network if matching
                # Check if mappedip matches an address object or subnet
                server_node_id = f"srv_{vdom_name}_{vip.mappedip.replace('.', '_')}"

                # Verify if we should create this internal server node
                topology["nodes"].append({
                    "id": server_node_id,
                    "label": f"Serveur\n{vip.mappedip}",
                    "type": "server",
                    "parent": vdom_node_id,
                    "details": {
                        "ip": vip.mappedip,
                        "vdom": vdom_name,
                        "description": "Serveur publié via VIP"
                    }
                })

                # Link VIP to internal Server
                topology["edges"].append({
                    "id": f"edge_vip_int_{vip_node_id}",
                    "source": vip_node_id,
                    "target": server_node_id,
                    "label": f"Port: {vip.mappedport}" if vip.portforward else "Tout",
                    "type": "vip_link"
                })

            # Sub-track for VPNs
            for vpn_name, vpn in vdom.vpns.items():
                vpn_node_id = f"vpn_{vdom_name}_{vpn_name.replace(' ', '_')}"

                topology["nodes"].append({
                    "id": vpn_node_id,
                    "label": f"VPN IPsec: {vpn_name}\nGW: {vpn.remote_gw or 'SSL'}",
                    "type": "vpn",
                    "parent": vdom_node_id,
                    "details": {
                        "name": vpn_name,
                        "type": vpn.type,
                        "remote_gw": vpn.remote_gw,
                        "local_subnet": vpn.local_subnet,
                        "remote_subnet": vpn.remote_subnet,
                        "vdom": vdom_name
                    }
                })

                # If remote gateway is known, draw a link to external site
                if vpn.remote_gw:
                    ext_site_id = f"site_dist_{vdom_name}_{vpn_name.replace(' ', '_')}"
                    topology["nodes"].append({
                        "id": ext_site_id,
                        "label": f"Site Distant\n({vpn.remote_gw})",
                        "type": "remote_site",
                        "details": {"gateway": vpn.remote_gw, "vpn": vpn_name}
                    })

                    # Connection between firewall/internet to external site
                    topology["edges"].append({
                        "id": f"edge_vpn_tunnel_{vpn_node_id}",
                        "source": vpn_node_id,
                        "target": ext_site_id,
                        "label": "Tunnel IPsec",
                        "type": "vpn_tunnel",
                        "dashed": True
                    })

                    # Also link vpn back to physical interface if configured
                    if vpn.interface:
                        ph_intf_id = f"intf_{vdom_name}_{vpn.interface.replace('/', '_').replace('.', '_')}"
                        topology["edges"].append({
                            "id": f"edge_vpn_parent_{vpn_node_id}",
                            "source": ph_intf_id,
                            "target": vpn_node_id,
                            "label": "Monté sur",
                            "type": "vpn_link"
                        })

            # Sub-track for explicit or inferred subnet networks from Address Objects
            for addr_name, addr in vdom.address_objects.items():
                if addr.type == "subnet" and addr.value and addr.value != "0.0.0.0/0":
                    # Create a subnet visual node
                    sub_node_id = f"subnet_{vdom_name}_{addr_name.replace(' ', '_')}"
                    topology["nodes"].append({
                        "id": sub_node_id,
                        "label": f"Subnet: {addr_name}\n{addr.value}",
                        "type": "subnet",
                        "parent": vdom_node_id,
                        "details": {
                            "name": addr_name,
                            "cidr": addr.value,
                            "vdom": vdom_name,
                            "interface": addr.associated_interface
                        }
                    })

                    # Link to its associated interface (explicit)
                    if addr.associated_interface and addr.associated_interface in vdom.interfaces:
                        intf_ref_id = f"intf_{vdom_name}_{addr.associated_interface.replace('/', '_').replace('.', '_')}"
                        topology["edges"].append({
                            "id": f"edge_sub_int_{sub_node_id}",
                            "source": intf_ref_id,
                            "target": sub_node_id,
                            "label": "Connecté",
                            "type": "subnet_link"
                        })
                    else:
                        # INFERRED RELATIONSHIP (Longest Prefix Match)
                        # Let's try to match the subnet value with any interface IP/mask
                        inferred_intf = RelationshipEngine.find_matching_interface(addr.value, vdom.interfaces)
                        if inferred_intf:
                            intf_ref_id = f"intf_{vdom_name}_{inferred_intf.replace('/', '_').replace('.', '_')}"
                            topology["edges"].append({
                                "id": f"edge_sub_int_inf_{sub_node_id}",
                                "source": intf_ref_id,
                                "target": sub_node_id,
                                "label": "Déduit (via IP)",
                                "type": "subnet_link_deduced",
                                "style": "dashed",
                                "details": {"logic": f"Le sous-réseau '{addr.value}' appartient à la plage d'IP de l'interface '{inferred_intf}'."}
                            })

        # 3. Inter-VDOM links detection & addition
        # Check system vdom-links
        # First, search all physical or virtual interfaces across vdoms to find links matching 'vdom-link'
        inter_vdoms_paired = []
        for vdom_name, vdom in device.vdoms.items():
            for ivl in vdom.inter_vdom_links:
                # FortiOS handles vdom-link with interface config. We will identify interfaces with type 'vdom-link'
                # or named similar. Let's do a cross VDOM lookup for interfaces sharing the same vdom-link name
                pass

        # Simple heuristic: if we have interfaces of type "vdom-link" across VDOMs with similar parent name, link them!
        vdom_links_list = {}
        for vdom_name, vdom in device.vdoms.items():
            for intf_name, intf in vdom.interfaces.items():
                # On newer FortiOS, a vdom-link interface edit block has "set type vdom-link" or name ends in '0' or '1'
                if intf.type == "vdom-link" or "vlink" in intf_name.lower():
                    # Strip trailing numbers or '0'/'1' to find pairs
                    base_name = re.sub(r'[01]$', '', intf_name)
                    vdom_links_list.setdefault(base_name, []).append((vdom_name, intf_name))

        for base, pairs in vdom_links_list.items():
            if len(pairs) >= 2:
                for idx in range(len(pairs) - 1):
                    va, ia = pairs[idx]
                    vb, ib = pairs[idx+1]
                    if va != vb: # link between separate VDOMs
                        node_a_id = f"intf_{va}_{ia.replace('/', '_').replace('.', '_')}"
                        node_b_id = f"intf_{vb}_{ib.replace('/', '_').replace('.', '_')}"
                        topology["edges"].append({
                            "id": f"edge_ivl_{va}_{vb}_{base}",
                            "source": node_a_id,
                            "target": node_b_id,
                            "label": f"Inter-VDOM ({base})",
                            "type": "inter_vdom_link",
                            "style": "bold"
                        })

        # 4. Policies as Flows
        for vdom_name, vdom in device.vdoms.items():
            for pol in vdom.policies:
                if pol.status == "disable":
                    continue
                # For each srcintf -> dstintf, draw an edge (flow)
                for src in pol.srcintf:
                    for dst in pol.dstintf:
                        # Find corresponding source & destination nodes in the graph
                        src_id = None
                        dst_id = None

                        # Source can be interface or zone
                        if src in vdom.zones:
                            src_id = f"zone_{vdom_name}_{src}"
                        elif src in vdom.interfaces:
                            src_id = f"intf_{vdom_name}_{src.replace('/', '_').replace('.', '_')}"
                        elif src.lower() == "any":
                            # map to any or vdom container
                            src_id = f"vdom_{vdom_name}"

                        # Destination can be interface or zone
                        if dst in vdom.zones:
                            dst_id = f"zone_{vdom_name}_{dst}"
                        elif dst in vdom.interfaces:
                            dst_id = f"intf_{vdom_name}_{dst.replace('/', '_').replace('.', '_')}"
                        elif dst.lower() == "any":
                            dst_id = f"vdom_{vdom_name}"

                        if src_id and dst_id and src_id != dst_id:
                            flow_id = f"flow_{vdom_name}_{pol.policy_id}_{src}_{dst}"
                            label_val = f"ID {pol.policy_id}"
                            if pol.name:
                                label_val += f" ({pol.name})"

                            topology["edges"].append({
                                "id": flow_id,
                                "source": src_id,
                                "target": dst_id,
                                "label": label_val,
                                "type": "policy_flow",
                                "details": {
                                    "policy_id": pol.policy_id,
                                    "name": pol.name,
                                    "vdom": vdom_name,
                                    "action": pol.action,
                                    "nat": pol.nat,
                                    "services": pol.service,
                                    "srcaddr": pol.srcaddr,
                                    "dstaddr": pol.dstaddr
                                }
                            })

        return topology

    @staticmethod
    def find_matching_interface(subnet_cidr, interfaces):
        """
        Calculates longest prefix match logic to map a subnet object
        to its matching internal physical/VLAN interface network.
        """
        # format: 192.168.1.0/24 or "192.168.1.0 255.255.255.0"
        sub_ip, sub_mask = RelationshipEngine.parse_cidr_or_mask(subnet_cidr)
        if not sub_ip or sub_ip == "0.0.0.0":
            return None

        for name, intf in interfaces.items():
            if intf.ip == "0.0.0.0":
                continue
            # Simple octet match comparison for IP networking
            intf_sub = RelationshipEngine.get_network_base(intf.ip, intf.mask)
            obj_sub = RelationshipEngine.get_network_base(sub_ip, sub_mask)
            if intf_sub == obj_sub and intf_sub != "0.0.0.0":
                return name
        return None

    @staticmethod
    def parse_cidr_or_mask(cidr_str):
        if not cidr_str:
            return None, None
        if "/" in cidr_str:
            parts = cidr_str.split("/")
            ip = parts[0]
            # convert cidr to subnet mask
            try:
                cidr = int(parts[1])
                mask = RelationshipEngine.cidr_to_mask(cidr)
                return ip, mask
            except ValueError:
                return ip, "255.255.255.0"
        elif " " in cidr_str:
            parts = cidr_str.split(" ")
            return parts[0], parts[1]
        return cidr_str, "255.255.255.255"

    @staticmethod
    def cidr_to_mask(cidr):
        host_bits = 32 - cidr
        netmask = (0xffffffff >> host_bits) << host_bits
        return f"{(netmask >> 24) & 0xff}.{(netmask >> 16) & 0xff}.{(netmask >> 8) & 0xff}.{netmask & 0xff}"

    @staticmethod
    def get_network_base(ip, mask):
        try:
            ip_parts = [int(x) for x in ip.split(".")]
            mask_parts = [int(x) for x in mask.split(".")]
            net_parts = [str(ip_parts[i] & mask_parts[i]) for i in range(4)]
            return ".".join(net_parts)
        except Exception:
            return "0.0.0.0"
