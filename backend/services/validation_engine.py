import re
from backend.models.models import Finding

class ValidationEngine:
    """
    Validates configuration consistency and flags anomalies.
    """
    @staticmethod
    def validate_device(device):
        findings = []

        # Track all subnets across all VDOMs to find overlapping/duplicates
        all_subnets = {} # subnet_str -> (vdom, type, name)

        for vdom_name, vdom in device.vdoms.items():
            # 1. Interfaces
            for intf_name, intf in vdom.interfaces.items():
                # Interface without IP address
                if intf.ip == "0.0.0.0" and intf.status == "up" and intf.type not in ["tunnel", "vlan", "lacp"]:
                    # Note: tunnels or VLAN parents might not have IPs, but physical ones should
                    findings.append(Finding(
                        category="interface",
                        severity="low",
                        description=f"L'interface physique '{intf_name}' est active mais n'a pas d'adresse IP configurée.",
                        item_type="Interface",
                        item_name=intf_name,
                        vdom=vdom_name
                    ))
                # Interface disabled but used
                # We can check if disabled interface is used in policies
                if intf.status == "down":
                    used_in_policy = False
                    for pol in vdom.policies:
                        if intf_name in pol.srcintf or intf_name in pol.dstintf:
                            used_in_policy = True
                            break
                    if used_in_policy:
                        findings.append(Finding(
                            category="interface",
                            severity="medium",
                            description=f"L'interface '{intf_name}' est désactivée (down) mais est référencée dans une règle de sécurité.",
                            item_type="Interface",
                            item_name=intf_name,
                            vdom=vdom_name
                        ))

            # 2. Zones
            for zone_name, zone in vdom.zones.items():
                if not zone.interfaces:
                    findings.append(Finding(
                        category="zone",
                        severity="medium",
                        description=f"La zone '{zone_name}' est vide (ne contient aucune interface membre).",
                        item_type="Zone",
                        item_name=zone_name,
                        vdom=vdom_name
                    ))

            # 3. Address objects & Groups
            unused_objects = set(vdom.address_objects.keys())
            for grp_name, grp in vdom.address_groups.items():
                if not grp.members:
                    findings.append(Finding(
                        category="object",
                        severity="low",
                        description=f"Le groupe d'adresses '{grp_name}' est vide.",
                        item_type="AddressGroup",
                        item_name=grp_name,
                        vdom=vdom_name
                    ))
                # If group is used, its members are in some way referenced, but let's check policies
                for m in grp.members:
                    if m in unused_objects:
                        unused_objects.discard(m)

            # Check policies to clear unused address objects
            for pol in vdom.policies:
                for s in pol.srcaddr:
                    unused_objects.discard(s)
                for d in pol.dstaddr:
                    unused_objects.discard(d)

            # Also check if VIPs use address objects, etc.
            for vip in vdom.vips.values():
                unused_objects.discard(vip.name)

            for obj_name in unused_objects:
                # Except some default objects like 'all'
                if obj_name.lower() not in ["all", "none", "any"]:
                    findings.append(Finding(
                        category="object",
                        severity="info",
                        description=f"L'objet adresse '{obj_name}' n'est utilisé dans aucune politique ou groupe d'adresses.",
                        item_type="AddressObject",
                        item_name=obj_name,
                        vdom=vdom_name
                    ))

            # Check for network overlaps across VDOMs
            for obj_name, obj in vdom.address_objects.items():
                if obj.type == "subnet" and obj.value and obj.value != "0.0.0.0/0":
                    sub = obj.value
                    if sub in all_subnets:
                        other_vdom, other_type, other_name = all_subnets[sub]
                        if other_vdom != vdom_name:
                            findings.append(Finding(
                                category="object",
                                severity="low",
                                description=f"Le sous-réseau '{sub}' (défini par '{obj_name}') apparaît également dans le VDOM '{other_vdom}' sous le nom '{other_name}'.",
                                item_type="AddressObject",
                                item_name=obj_name,
                                vdom=vdom_name
                            ))
                    else:
                        all_subnets[sub] = (vdom_name, "AddressObject", obj_name)

            # 4. Routes using non-existent interfaces
            for r in vdom.routes:
                if r.device and r.device not in vdom.interfaces:
                    # check if it is a VPN interface or something global
                    is_vpn = False
                    for vpn in vdom.vpns.values():
                        if vpn.name == r.device or vpn.interface == r.device:
                            is_vpn = True
                            break
                    if not is_vpn and r.device.lower() not in ["blackhole", "null"]:
                        findings.append(Finding(
                            category="routing",
                            severity="high",
                            description=f"La route vers '{r.destination}' utilise l'interface inexistante '{r.device}'.",
                            item_type="Route",
                            item_name=r.destination,
                            vdom=vdom_name
                        ))

            # 5. Firewall Policies Validation
            for pol in vdom.policies:
                # Check for "Any vers Any" rule
                is_any_src = "all" in [s.lower() for s in pol.srcaddr] or "any" in [s.lower() for s in pol.srcaddr]
                is_any_dst = "all" in [d.lower() for d in pol.dstaddr] or "any" in [d.lower() for d in pol.dstaddr]
                is_any_srv = "all" in [srv.lower() for srv in pol.service] or "any" in [srv.lower() for srv in pol.service]

                if is_any_src and is_any_dst and is_any_srv and pol.action == "accept" and pol.status == "enable":
                    findings.append(Finding(
                        category="policy",
                        severity="high",
                        description=f"Règle '{pol.policy_id}' ({pol.name or 'sans nom'}) autorise TOUT le trafic (Any to Any).",
                        item_type="FirewallPolicy",
                        item_name=str(pol.policy_id),
                        vdom=vdom_name
                    ))

                # Disabled rule
                if pol.status == "disable":
                    findings.append(Finding(
                        category="policy",
                        severity="info",
                        description=f"Règle '{pol.policy_id}' ({pol.name or 'sans nom'}) est désactivée.",
                        item_type="FirewallPolicy",
                        item_name=str(pol.policy_id),
                        vdom=vdom_name
                    ))

                # Rules without logging
                if pol.logtraffic == "disable" and pol.action == "accept":
                    findings.append(Finding(
                        category="policy",
                        severity="low",
                        description=f"Règle '{pol.policy_id}' autorise le flux sans journalisation (logtraffic désactivé).",
                        item_type="FirewallPolicy",
                        item_name=str(pol.policy_id),
                        vdom=vdom_name
                    ))

                # Rules with ALL service (accept)
                if is_any_srv and pol.action == "accept" and not (is_any_src and is_any_dst):
                    findings.append(Finding(
                        category="policy",
                        severity="medium",
                        description=f"Règle '{pol.policy_id}' autorise le service 'ALL/ANY' entre '{', '.join(pol.srcintf)}' et '{', '.join(pol.dstintf)}'.",
                        item_type="FirewallPolicy",
                        item_name=str(pol.policy_id),
                        vdom=vdom_name
                    ))

                # Rules using missing interfaces
                for src_i in pol.srcintf:
                    if src_i.lower() not in ["any"] and src_i not in vdom.interfaces and src_i not in vdom.zones:
                        findings.append(Finding(
                            category="policy",
                            severity="high",
                            description=f"Règle '{pol.policy_id}' utilise une interface ou zone source inexistante '{src_i}'.",
                            item_type="FirewallPolicy",
                            item_name=str(pol.policy_id),
                            vdom=vdom_name
                        ))
                for dst_i in pol.dstintf:
                    if dst_i.lower() not in ["any"] and dst_i not in vdom.interfaces and dst_i not in vdom.zones:
                        findings.append(Finding(
                            category="policy",
                            severity="high",
                            description=f"Règle '{pol.policy_id}' utilise une interface ou zone de destination inexistante '{dst_i}'.",
                            item_type="FirewallPolicy",
                            item_name=str(pol.policy_id),
                            vdom=vdom_name
                        ))

                # Rules using missing objects
                for s_obj in pol.srcaddr:
                    if s_obj.lower() not in ["all", "any"] and s_obj not in vdom.address_objects and s_obj not in vdom.address_groups and s_obj not in vdom.vips:
                        findings.append(Finding(
                            category="policy",
                            severity="high",
                            description=f"Règle '{pol.policy_id}' fait référence à un objet adresse source inexistant '{s_obj}'.",
                            item_type="FirewallPolicy",
                            item_name=str(pol.policy_id),
                            vdom=vdom_name
                        ))
                for d_obj in pol.dstaddr:
                    if d_obj.lower() not in ["all", "any"] and d_obj not in vdom.address_objects and d_obj not in vdom.address_groups and d_obj not in vdom.vips:
                        findings.append(Finding(
                            category="policy",
                            severity="high",
                            description=f"Règle '{pol.policy_id}' fait référence à un objet adresse de destination inexistant '{d_obj}'.",
                            item_type="FirewallPolicy",
                            item_name=str(pol.policy_id),
                            vdom=vdom_name
                        ))

            # 6. VIPs Validation
            for vip_name, vip in vdom.vips.items():
                # Check if VIP is used in policies
                vip_used = False
                for pol in vdom.policies:
                    if vip_name in pol.dstaddr:
                        vip_used = True
                        break
                if not vip_used:
                    findings.append(Finding(
                        category="vip",
                        severity="low",
                        description=f"Le VIP '{vip_name}' ({vip.extip} -> {vip.mappedip}) n'est utilisé dans aucune politique de sécurité.",
                        item_type="VIP",
                        item_name=vip_name,
                        vdom=vdom_name
                    ))

            # 7. VPN Tunnels Validation
            for vpn_name, vpn in vdom.vpns.items():
                if vpn.type == "ipsec":
                    # Check if there is an interface mapping or route associated
                    route_found = False
                    for r in vdom.routes:
                        if r.device == vpn_name or r.device == vpn.interface:
                            route_found = True
                            break
                    if not route_found:
                        findings.append(Finding(
                            category="vpn",
                            severity="medium",
                            description=f"Le tunnel VPN IPsec '{vpn_name}' n'a pas de route statique/dynamique associée.",
                            item_type="VPN",
                            item_name=vpn_name,
                            vdom=vdom_name
                        ))

        device.findings = findings
        return findings
