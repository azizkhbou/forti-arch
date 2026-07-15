import csv
import io

class ReportExporter:
    """
    Handles CSV exports for all different inventaires.
    """
    @staticmethod
    def generate_inventory_csv(device, item_type):
        """
        Gathers requested elements across all VDOMs and writes them to a CSV string.
        item_type can be: vdoms, interfaces, zones, vlans, routes, objects, address_groups, services, service_groups, policies, vips, ippools, vpns, inter_vdom_links
        """
        output = io.StringIO()
        writer = csv.writer(output)

        if item_type == "vdoms":
            writer.writerow(["VDOM", "Mode", "Interfaces Count", "Policies Count", "Routes Count"])
            for name, vdom in device.vdoms.items():
                writer.writerow([
                    vdom.name,
                    vdom.mode,
                    len(vdom.interfaces),
                    len(vdom.policies),
                    len(vdom.routes)
                ])

        elif item_type == "interfaces":
            writer.writerow(["VDOM", "Nom", "Alias", "Type", "IP", "Masque", "Rôle", "VLAN ID", "Statut", "Accès Admin", "DHCP"])
            for v_name, vdom in device.vdoms.items():
                for name, intf in vdom.interfaces.items():
                    writer.writerow([
                        v_name, intf.name, intf.alias, intf.type, intf.ip, intf.mask,
                        intf.role, intf.vlan_id or "", intf.status, ",".join(intf.admin_access), intf.dhcp_mode
                    ])

        elif item_type == "zones":
            writer.writerow(["VDOM", "Zone", "Interfaces Membres", "Intrazone", "Rôle Supposé"])
            for v_name, vdom in device.vdoms.items():
                for name, zone in vdom.zones.items():
                    writer.writerow([
                        v_name, zone.name, ",".join(zone.interfaces), zone.intrazone, zone.role
                    ])

        elif item_type == "routes":
            writer.writerow(["VDOM", "Destination", "Passerelle (GW)", "Interface", "Distance", "Priorité", "Type", "Blackhole"])
            for v_name, vdom in device.vdoms.items():
                for r in vdom.routes:
                    writer.writerow([
                        v_name, r.destination, r.gateway, r.device, r.distance, r.priority, r.type, r.blackhole
                    ])

        elif item_type == "objects":
            writer.writerow(["VDOM", "Nom", "Type", "Valeur/IP", "Interface Associée"])
            for v_name, vdom in device.vdoms.items():
                for name, obj in vdom.address_objects.items():
                    writer.writerow([
                        v_name, obj.name, obj.type, obj.value, obj.associated_interface
                    ])

        elif item_type == "address_groups":
            writer.writerow(["VDOM", "Nom Groupe", "Membres"])
            for v_name, vdom in device.vdoms.items():
                for name, grp in vdom.address_groups.items():
                    writer.writerow([
                        v_name, grp.name, ",".join(grp.members)
                    ])

        elif item_type == "services":
            writer.writerow(["VDOM", "Nom", "Protocole", "Ports/Type ICMP"])
            for v_name, vdom in device.vdoms.items():
                for name, srv in vdom.service_objects.items():
                    writer.writerow([
                        v_name, srv.name, srv.protocol, srv.ports
                    ])

        elif item_type == "policies":
            writer.writerow(["VDOM", "ID Règle", "Nom", "Source Intf/Zone", "Dest Intf/Zone", "Sources Addr", "Dests Addr", "Services", "Action", "NAT", "Pool IP", "Statut", "Commentaire"])
            for v_name, vdom in device.vdoms.items():
                for pol in vdom.policies:
                    writer.writerow([
                        v_name, pol.policy_id, pol.name,
                        ",".join(pol.srcintf), ",".join(pol.dstintf),
                        ",".join(pol.srcaddr), ",".join(pol.dstaddr),
                        ",".join(pol.service), pol.action, pol.nat, pol.ippool, pol.status, pol.comments
                    ])

        elif item_type == "vips":
            writer.writerow(["VDOM", "Nom VIP", "IP Externe", "IP Interne", "Intf Ext", "Port Forwarding", "Port Ext", "Port Int"])
            for v_name, vdom in device.vdoms.items():
                for name, vip in vdom.vips.items():
                    writer.writerow([
                        v_name, vip.name, vip.extip, vip.mappedip, vip.extintf,
                        vip.portforward, vip.extport, vip.mappedport
                    ])

        elif item_type == "vpns":
            writer.writerow(["VDOM", "Nom VPN", "Type", "Passerelle Distante", "Interface Locale", "Réseau Local", "Réseau Distant", "Port SSL", "Portail SSL"])
            for v_name, vdom in device.vdoms.items():
                for name, vpn in vdom.vpns.items():
                    writer.writerow([
                        v_name, vpn.name, vpn.type, vpn.remote_gw, vpn.interface,
                        vpn.local_subnet, vpn.remote_subnet, vpn.ssl_port, vpn.ssl_portal
                    ])

        else:
            # Fallback empty
            writer.writerow(["Inventaire indisponible"])

        return output.getvalue()
