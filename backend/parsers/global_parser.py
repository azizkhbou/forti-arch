import re
from backend.parsers.fortigate_parser import parse_raw_config
from backend.models.models import (
    FortiGateModel, VdomModel, InterfaceModel, ZoneModel,
    AddressObjectModel, AddressGroupModel, ServiceObjectModel, ServiceGroupModel,
    RouteModel, FirewallPolicyModel, VIPModel, IPPoolModel, VPNModel, InterVdomLinkModel
)

def build_parsed_model(global_node, global_lines, global_filename, vdom_files_data=None):
    """
    Combines parsed global node structure and optional separate VDOM nodes
    to return a complete, unified FortiGateModel object.

    vdom_files_data: list of dict {'filename': str, 'vdom_name': str, 'content': str}
    """
    device = FortiGateModel()

    # 1. Extract Global/Root Metadata
    system_global = global_node.find_child("config", "system global")
    if system_global:
        device.hostname = system_global.get_setting("hostname", "FortiGate")

    # Let's count total lines from all parsed configs
    total_lines = len(global_lines)

    # Check for VDOM list in global node
    vdom_config = global_node.find_child("config", "system vdom-property")
    detected_vdom_names = ["root"] # default VDOM

    # If VDOM mode is enabled in global, find the system vdom list
    sys_vdom_config = global_node.find_child("config", "vdom") or global_node.find_child("config", "system vdom")
    if sys_vdom_config:
        for edit_vdom in sys_vdom_config.find_all_children("edit"):
            detected_vdom_names.append(edit_vdom.name)

    # Unique names
    detected_vdom_names = list(set(detected_vdom_names))

    # Initialize all detected VDOM models
    for v_name in detected_vdom_names:
        device.vdoms[v_name] = VdomModel(v_name)

    # Parse Global node configurations
    parse_node_into_device(global_node, global_lines, global_filename, device)

    # Parse alternate separate VDOM files
    if vdom_files_data:
        for v_data in vdom_files_data:
            v_content = v_data['content']
            v_name = v_data['vdom_name']
            v_fn = v_data['filename']

            vdom_root_node, vdom_lines = parse_raw_config(v_content, v_fn)
            total_lines += len(vdom_lines)

            if v_name not in device.vdoms:
                device.vdoms[v_name] = VdomModel(v_name)

            parse_node_into_device(vdom_root_node, vdom_lines, v_fn, device, target_vdom=v_name)

    # Clean duplicates & calculate completeness/counts
    calculate_quality_metrics(device, total_lines)

    return device


def parse_node_into_device(root_node, all_lines, filename, device, target_vdom=None):
    """
    Iterates over sections in config tree and parses them into the device model.
    If target_vdom is supplied, force sections without specified vdom into it.
    """
    # Helper to clean lists from multiline settings like "set member user1 user2"
    def split_members(member_str):
        if not member_str:
            return []
        # split by whitespace but respect quotes
        return [m.strip('"') for m in re.findall(r'(?:[^\s"]|"(?:\\.|[^"])*")+', member_str)]

    # 1. Parse system global settings if present
    sys_glob = root_node.find_child("config", "system global")
    if sys_glob:
        device.hostname = sys_glob.get_setting("hostname", device.hostname)
        device.version = sys_glob.get_setting("version", device.version)
        device.model = sys_glob.get_setting("model", device.model)
        device.serial_number = sys_glob.get_setting("serial", device.serial_number)

    # Let's search inside the node for specific "config" blocks.
    # Note that in FortiGate, VDOMs can be declared in "config vdom" -> "edit VDOM_NAME" -> "config ..."
    # Or config blocks can be directly at root (for single VDOM or global configurations).

    # We will traverse the tree to find all relevant 'config <type>' blocks
    config_blocks = []

    # Simple recursive function to find all 'config' and 'edit' nodes
    def traverse(node, current_vdom):
        # Determine VDOM context
        new_vdom = current_vdom
        if node.type_name == "config" and node.name == "vdom":
            # Inside config vdom
            for edit_node in node.find_all_children("edit"):
                v_name = edit_node.name
                if v_name not in device.vdoms:
                    device.vdoms[v_name] = VdomModel(v_name)
                # Traverse inside this edit vdom block with VDOM context
                for child in edit_node.children:
                    traverse(child, v_name)
            return

        # If there's config block
        if node.type_name == "config":
            config_blocks.append((node, current_vdom or target_vdom or "root"))

        for child in node.children:
            traverse(child, current_vdom)

    traverse(root_node, target_vdom)

    # Parse extracted config blocks
    for config_node, vdom_name in config_blocks:
        vdom = device.vdoms.setdefault(vdom_name, VdomModel(vdom_name))

        # --- 1. System Interfaces ---
        if config_node.name == "system interface":
            for edit_node in config_node.find_all_children("edit"):
                intf_name = edit_node.name
                intf = vdom.interfaces.setdefault(intf_name, InterfaceModel(intf_name))
                intf.vdom = vdom_name
                intf.source_file = filename
                intf.start_line = edit_node.start_line
                intf.raw_config = edit_node.get_block_lines(all_lines)

                intf.alias = edit_node.get_setting("alias", intf.alias)
                intf.type = edit_node.get_setting("type", intf.type)

                ip_mask = edit_node.get_setting("ip", "0.0.0.0 0.0.0.0")
                if ip_mask and " " in ip_mask:
                    parts = ip_mask.split(" ")
                    intf.ip = parts[0]
                    intf.mask = parts[1]
                else:
                    intf.ip = ip_mask

                intf.role = edit_node.get_setting("role", intf.role)
                vlan_val = edit_node.get_setting("vlanid")
                if vlan_val:
                    try:
                        intf.vlan_id = int(vlan_val)
                        intf.type = "vlan"
                    except ValueError:
                        pass

                intf.interface_parent = edit_node.get_setting("interface", intf.interface_parent)
                status_val = edit_node.get_setting("status")
                if status_val:
                    intf.status = status_val # up, down

                allowaccess = edit_node.get_setting("allowaccess", "")
                if allowaccess:
                    intf.admin_access = split_members(allowaccess)

                # Check for physical port or lag
                if edit_node.get_setting("lacp-speed"):
                    intf.type = "lacp"

                # Associated VDOM might be overwritten via set vdom
                vdom_set = edit_node.get_setting("vdom")
                if vdom_set and vdom_set in device.vdoms:
                    intf.vdom = vdom_set
                    # move to correct vdom list
                    if intf_name in vdom.interfaces:
                        del vdom.interfaces[intf_name]
                    target_v = device.vdoms[vdom_set]
                    target_v.interfaces[intf_name] = intf

        # --- 2. System Zones ---
        elif config_node.name == "system zone":
            for edit_node in config_node.find_all_children("edit"):
                z_name = edit_node.name
                zone = vdom.zones.setdefault(z_name, ZoneModel(z_name))
                zone.vdom = vdom_name
                zone.source_file = filename
                zone.start_line = edit_node.start_line
                zone.raw_config = edit_node.get_block_lines(all_lines)

                intfs = edit_node.get_setting("interface", "")
                if intfs:
                    zone.interfaces = split_members(intfs)

                intra = edit_node.get_setting("intrazone", "deny")
                zone.intrazone = intra

                # guess role based on name
                lower_name = z_name.lower()
                if "lan" in lower_name or "usr" in lower_name:
                    zone.role = "LAN"
                elif "wan" in lower_name or "inet" in lower_name or "internet" in lower_name:
                    zone.role = "WAN"
                elif "dmz" in lower_name:
                    zone.role = "DMZ"
                elif "srv" in lower_name or "server" in lower_name:
                    zone.role = "server"
                elif "adm" in lower_name or "mgmt" in lower_name:
                    zone.role = "administration"

        # --- 3. Address Objects ---
        elif config_node.name == "firewall address":
            for edit_node in config_node.find_all_children("edit"):
                addr_name = edit_node.name
                addr = vdom.address_objects.setdefault(addr_name, AddressObjectModel(addr_name))
                addr.vdom = vdom_name
                addr.source_file = filename
                addr.start_line = edit_node.start_line
                addr.raw_config = edit_node.get_block_lines(all_lines)

                # Check type
                type_val = edit_node.get_setting("type", "subnet")
                addr.type = type_val

                if type_val == "subnet" or type_val == "ip":
                    subnet_val = edit_node.get_setting("subnet")
                    if subnet_val:
                        addr.value = subnet_val
                elif type_val == "iprange":
                    start_ip = edit_node.get_setting("start-ip", "")
                    end_ip = edit_node.get_setting("end-ip", "")
                    addr.value = f"{start_ip}-{end_ip}" if end_ip else start_ip
                elif type_val == "fqdn":
                    addr.value = edit_node.get_setting("fqdn", "")
                elif type_val == "wildcard":
                    addr.value = edit_node.get_setting("wildcard", "")
                elif type_val == "geography":
                    addr.value = edit_node.get_setting("country", "")
                elif type_val == "dynamic":
                    addr.value = edit_node.get_setting("sub-type", "")

                # If value is empty, try default subnet setting format directly
                if not addr.value:
                    sub_fallback = edit_node.get_setting("subnet")
                    if sub_fallback:
                        addr.value = sub_fallback

                addr.associated_interface = edit_node.get_setting("associated-interface", "")

        # --- 4. Address Groups ---
        elif config_node.name == "firewall addrgrp":
            for edit_node in config_node.find_all_children("edit"):
                g_name = edit_node.name
                group = vdom.address_groups.setdefault(g_name, AddressGroupModel(g_name))
                group.vdom = vdom_name
                group.source_file = filename
                group.start_line = edit_node.start_line
                group.raw_config = edit_node.get_block_lines(all_lines)

                members_str = edit_node.get_setting("member", "")
                group.members = split_members(members_str)

        # --- 5. Service Objects ---
        elif config_node.name == "firewall service custom":
            for edit_node in config_node.find_all_children("edit"):
                srv_name = edit_node.name
                srv = vdom.service_objects.setdefault(srv_name, ServiceObjectModel(srv_name))
                srv.vdom = vdom_name
                srv.source_file = filename
                srv.start_line = edit_node.start_line
                srv.raw_config = edit_node.get_block_lines(all_lines)

                protocol_val = edit_node.get_setting("protocol", "TCP/UDP/SCTP")
                tcp_port = edit_node.get_setting("tcp-portrange", "")
                udp_port = edit_node.get_setting("udp-portrange", "")

                if tcp_port:
                    srv.protocol = "TCP"
                    srv.ports = tcp_port
                elif udp_port:
                    srv.protocol = "UDP"
                    srv.ports = udp_port
                elif "icmp" in protocol_val.lower():
                    srv.protocol = "ICMP"
                    srv.ports = edit_node.get_setting("icmptype", "")
                else:
                    srv.protocol = protocol_val
                    srv.ports = ""

        # --- 6. Service Groups ---
        elif config_node.name == "firewall service group":
            for edit_node in config_node.find_all_children("edit"):
                g_name = edit_node.name
                group = vdom.service_groups.setdefault(g_name, ServiceGroupModel(g_name))
                group.vdom = vdom_name
                group.source_file = filename
                group.start_line = edit_node.start_line
                group.raw_config = edit_node.get_block_lines(all_lines)

                members_str = edit_node.get_setting("member", "")
                group.members = split_members(members_str)

        # --- 7. Firewall Policies ---
        elif config_node.name == "firewall policy":
            for edit_node in config_node.find_all_children("edit"):
                p_id = edit_node.name
                policy = FirewallPolicyModel(p_id)
                policy.vdom = vdom_name
                policy.source_file = filename
                policy.start_line = edit_node.start_line
                policy.raw_config = edit_node.get_block_lines(all_lines)

                policy.name = edit_node.get_setting("name", "")
                policy.srcintf = split_members(edit_node.get_setting("srcintf", ""))
                policy.dstintf = split_members(edit_node.get_setting("dstintf", ""))
                policy.srcaddr = split_members(edit_node.get_setting("srcaddr", ""))
                policy.dstaddr = split_members(edit_node.get_setting("dstaddr", ""))
                policy.service = split_members(edit_node.get_setting("service", ""))

                act_val = edit_node.get_setting("action", "deny")
                policy.action = act_val

                nat_val = edit_node.get_setting("nat", "disable")
                policy.nat = (nat_val == "enable")
                policy.ippool = edit_node.get_setting("ippool", "")

                ssl_val = edit_node.get_setting("ssl-ssh-profile")
                if ssl_val and ssl_val != "no-inspection":
                    policy.ssl_inspection = True

                policy.ips_sensor = edit_node.get_setting("ips-sensor", "")
                policy.av_profile = edit_node.get_setting("av-profile", "")
                policy.webfilter_profile = edit_node.get_setting("webfilter-profile", "")
                policy.app_control = edit_node.get_setting("application-list", "")
                policy.logtraffic = edit_node.get_setting("logtraffic", "disable")
                policy.status = edit_node.get_setting("status", "enable")
                policy.schedule = edit_node.get_setting("schedule", "always")
                policy.comments = edit_node.get_setting("comments", "")
                policy.order = len(vdom.policies) + 1

                vdom.policies.append(policy)

        # --- 8. Routes ---
        elif config_node.name == "router static":
            for edit_node in config_node.find_all_children("edit"):
                route = RouteModel()
                route.vdom = vdom_name
                route.type = "static"
                route.source_file = filename
                route.start_line = edit_node.start_line
                route.raw_config = edit_node.get_block_lines(all_lines)

                dst_val = edit_node.get_setting("dst", "0.0.0.0/0")
                if dst_val and " " in dst_val: # IP Mask notation
                    p = dst_val.split(" ")
                    # Convert subnet to CIDR if needed
                    route.destination = dst_val # can keep original or CIDR
                else:
                    route.destination = dst_val

                route.gateway = edit_node.get_setting("gateway", "0.0.0.0")
                route.device = edit_node.get_setting("device", "")

                dist_val = edit_node.get_setting("distance")
                if dist_val:
                    try: route.distance = int(dist_val)
                    except ValueError: pass

                pri_val = edit_node.get_setting("priority")
                if pri_val:
                    try: route.priority = int(pri_val)
                    except ValueError: pass

                blackhole_val = edit_node.get_setting("blackhole", "disable")
                route.blackhole = (blackhole_val == "enable")

                # If destination is 0.0.0.0 0.0.0.0 or similar, it's a default route
                if route.destination in ["0.0.0.0 0.0.0.0", "0.0.0.0/0"]:
                    route.type = "default"

                vdom.routes.append(route)

        # --- 9. Virtual IP (VIP) ---
        elif config_node.name == "firewall vip":
            for edit_node in config_node.find_all_children("edit"):
                vip_name = edit_node.name
                vip = vdom.vips.setdefault(vip_name, VIPModel(vip_name))
                vip.vdom = vdom_name
                vip.source_file = filename
                vip.start_line = edit_node.start_line
                vip.raw_config = edit_node.get_block_lines(all_lines)

                vip.extip = edit_node.get_setting("extip", "")
                vip.mappedip = edit_node.get_setting("mappedip", "")
                vip.extintf = edit_node.get_setting("extintf", "any")

                pf_val = edit_node.get_setting("portforward", "disable")
                vip.portforward = (pf_val == "enable")
                vip.extport = edit_node.get_setting("extport", "")
                vip.mappedport = edit_node.get_setting("mappedport", "")

        # --- 10. IP Pools ---
        elif config_node.name == "firewall ippool":
            for edit_node in config_node.find_all_children("edit"):
                p_name = edit_node.name
                pool = vdom.ip_pools.setdefault(p_name, IPPoolModel(p_name))
                pool.vdom = vdom_name
                pool.source_file = filename
                pool.start_line = edit_node.start_line
                pool.raw_config = edit_node.get_block_lines(all_lines)

                pool.startip = edit_node.get_setting("startip", "")
                pool.endip = edit_node.get_setting("endip", "")

        # --- 11. VPN (IPsec / SSL) ---
        elif config_node.name in ["vpn ipsec phase1", "vpn ipsec phase1-interface"]:
            for edit_node in config_node.find_all_children("edit"):
                vpn_name = edit_node.name
                vpn = vdom.vpns.setdefault(vpn_name, VPNModel(vpn_name))
                vpn.vdom = vdom_name
                vpn.type = "ipsec"
                vpn.source_file = filename
                vpn.start_line = edit_node.start_line
                vpn.raw_config = edit_node.get_block_lines(all_lines)

                vpn.remote_gw = edit_node.get_setting("remote-gw", "")
                vpn.interface = edit_node.get_setting("interface", "")

        # Also grab IPsec Phase 2 details if they map to same name
        elif config_node.name in ["vpn ipsec phase2", "vpn ipsec phase2-interface"]:
            for edit_node in config_node.find_all_children("edit"):
                vpn_name = edit_node.get_setting("phase1name", "")
                if vpn_name and vpn_name in vdom.vpns:
                    vpn = vdom.vpns[vpn_name]
                    # Append local/remote subnet info if available
                    src_addr = edit_node.get_setting("src-subnet", "")
                    dst_addr = edit_node.get_setting("dst-subnet", "")
                    if src_addr: vpn.local_subnet = src_addr
                    if dst_addr: vpn.remote_subnet = dst_addr

        # SSL-VPN
        elif config_node.name == "vpn ssl settings":
            vpn_name = "SSL_VPN"
            vpn = vdom.vpns.setdefault(vpn_name, VPNModel(vpn_name))
            vpn.vdom = vdom_name
            vpn.type = "ssl-vpn"
            vpn.source_file = filename
            vpn.start_line = config_node.start_line
            vpn.raw_config = config_node.get_block_lines(all_lines)

            vpn.ssl_port = config_node.get_setting("serverport", "443")
            # Map portal/address pool
            vpn.ssl_portal = config_node.get_setting("default-portal", "")

        # --- 12. Inter-VDOM links ---
        elif config_node.name == "system vdom-link":
            for edit_node in config_node.find_all_children("edit"):
                link_name = edit_node.name
                ivl = InterVdomLinkModel(link_name)
                ivl.source_file = filename
                ivl.start_line = edit_node.start_line
                ivl.raw_config = edit_node.get_block_lines(all_lines)

                # Name of vdom-link can be associated with Interfaces.
                # We will analyze relations in relationship_engine.
                vdom.inter_vdom_links.append(ivl)


def calculate_quality_metrics(device, total_lines):
    """
    Computes quality counts and estimates completeness percentage.
    """
    num_vdoms = len(device.vdoms)
    num_interfaces = 0
    num_zones = 0
    num_vlans = 0
    num_routes = 0
    num_policies = 0
    num_vips = 0
    num_vpns = 0
    num_objects = 0

    for v_name, vdom in device.vdoms.items():
        num_interfaces += len(vdom.interfaces)
        num_zones += len(vdom.zones)
        num_routes += len(vdom.routes)
        num_policies += len(vdom.policies)
        num_vips += len(vdom.vips)
        num_vpns += len(vdom.vpns)
        num_objects += len(vdom.address_objects) + len(vdom.address_groups) + len(vdom.service_objects) + len(vdom.service_groups)

        # count vlans
        for intf in vdom.interfaces.values():
            if intf.vlan_id is not None:
                num_vlans += 1

    device.quality_report["lines_analyzed"] = total_lines
    device.quality_report["vdoms_detected"] = num_vdoms
    device.quality_report["interfaces"] = num_interfaces
    device.quality_report["zones"] = num_zones
    device.quality_report["vlans"] = num_vlans
    device.quality_report["routes"] = num_routes
    device.quality_report["policies"] = num_policies
    device.quality_report["vips"] = num_vips
    device.quality_report["vpns"] = num_vpns
    device.quality_report["objects"] = num_objects

    # Simple completeness estimation based on core elements extracted
    base = 100
    if num_interfaces == 0: base -= 25
    if num_policies == 0: base -= 25
    if num_routes == 0: base -= 15
    if num_objects == 0: base -= 15
    if num_vdoms == 0: base -= 20

    device.quality_report["completeness"] = max(10, base)
