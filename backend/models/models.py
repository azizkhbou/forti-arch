import re

class FortiGateModel:
    """
    Unified Data Model for FortiGate Device
    """
    def __init__(self):
        # Global Metadata
        self.hostname = "FortiGate"
        self.model = "Unknown"
        self.version = "Unknown"
        self.serial_number = "Unknown"
        self.quality_report = {
            "lines_analyzed": 0,
            "vdoms_detected": 0,
            "interfaces": 0,
            "zones": 0,
            "vlans": 0,
            "routes": 0,
            "policies": 0,
            "vips": 0,
            "vpns": 0,
            "objects": 0,
            "uninterpreted_lines": 0,
            "completeness": 100
        }

        # System Lists
        self.vdoms = {}  # vdom_name -> VdomModel
        self.findings = []  # List of Finding objects

    def to_dict(self):
        return {
            "hostname": self.hostname,
            "model": self.model,
            "version": self.version,
            "serial_number": self.serial_number,
            "quality_report": self.quality_report,
            "vdoms": {k: v.to_dict() for k, v in self.vdoms.items()},
            "findings": [f.to_dict() for f in self.findings]
        }


class VdomModel:
    def __init__(self, name):
        self.name = name
        self.mode = "NAT"  # NAT or transparent
        self.interfaces = {}  # name -> InterfaceModel
        self.zones = {}  # name -> ZoneModel
        self.address_objects = {}  # name -> AddressObjectModel
        self.address_groups = {}  # name -> AddressGroupModel
        self.service_objects = {}  # name -> ServiceObjectModel
        self.service_groups = {}  # name -> ServiceGroupModel
        self.policies = []  # List of FirewallPolicyModel
        self.routes = []  # List of RouteModel
        self.vips = {}  # name -> VIPModel
        self.ip_pools = {}  # name -> IPPoolModel
        self.vpns = {}  # name -> VPNModel
        self.inter_vdom_links = []  # List of InterVdomLinkModel

    def to_dict(self):
        return {
            "name": self.name,
            "mode": self.mode,
            "interfaces": {k: v.to_dict() for k, v in self.interfaces.items()},
            "zones": {k: v.to_dict() for k, v in self.zones.items()},
            "address_objects": {k: v.to_dict() for k, v in self.address_objects.items()},
            "address_groups": {k: v.to_dict() for k, v in self.address_groups.items()},
            "service_objects": {k: v.to_dict() for k, v in self.service_objects.items()},
            "service_groups": {k: v.to_dict() for k, v in self.service_groups.items()},
            "policies": [p.to_dict() for p in self.policies],
            "routes": [r.to_dict() for r in self.routes],
            "vips": {k: v.to_dict() for k, v in self.vips.items()},
            "ip_pools": {k: v.to_dict() for k, v in self.ip_pools.items()},
            "vpns": {k: v.to_dict() for k, v in self.vpns.items()},
            "inter_vdom_links": [l.to_dict() for l in self.inter_vdom_links]
        }


class InterfaceModel:
    def __init__(self, name):
        self.id = "intf_" + name.replace("/", "_").replace(".", "_")
        self.name = name
        self.alias = ""
        self.type = "physical"  # physical, vlan, loopback, tunnel, vdom-link, lacp, aggregate
        self.vdom = "root"
        self.ip = "0.0.0.0"
        self.mask = "0.0.0.0"
        self.role = "undefined"  # lan, wan, dmz, undefined
        self.vlan_id = None
        self.interface_parent = ""
        self.status = "up"  # up, down
        self.admin_access = []  # ping, https, ssh, etc.
        self.dhcp_mode = "none"  # server, relay, none
        self.zone = ""
        self.lacp_members = []
        self.source_file = ""
        self.start_line = 0
        self.raw_config = ""

    def to_dict(self):
        return self.__dict__


class ZoneModel:
    def __init__(self, name):
        self.id = "zone_" + name
        self.name = name
        self.vdom = "root"
        self.interfaces = []
        self.intrazone = "deny"  # allow, deny
        self.role = "undefined"  # LAN, WAN, DMZ, etc.
        self.source_file = ""
        self.start_line = 0
        self.raw_config = ""

    def to_dict(self):
        return self.__dict__


class AddressObjectModel:
    def __init__(self, name):
        self.id = "addr_" + name.replace(" ", "_")
        self.name = name
        self.type = "subnet"  # subnet, iprange, fqdn, wildcard, geography, dynamic
        self.value = ""  # subnet CIDR, range, domain name, etc
        self.associated_interface = ""
        self.vdom = "root"
        self.source_file = ""
        self.start_line = 0
        self.raw_config = ""

    def to_dict(self):
        return self.__dict__


class AddressGroupModel:
    def __init__(self, name):
        self.id = "addrgrp_" + name.replace(" ", "_")
        self.name = name
        self.members = []
        self.vdom = "root"
        self.source_file = ""
        self.start_line = 0
        self.raw_config = ""

    def to_dict(self):
        return self.__dict__


class ServiceObjectModel:
    def __init__(self, name):
        self.id = "srv_" + name.replace(" ", "_")
        self.name = name
        self.protocol = "TCP"  # TCP, UDP, ICMP, IP
        self.ports = ""  # port/range
        self.vdom = "root"
        self.source_file = ""
        self.start_line = 0
        self.raw_config = ""

    def to_dict(self):
        return self.__dict__


class ServiceGroupModel:
    def __init__(self, name):
        self.id = "srvgrp_" + name.replace(" ", "_")
        self.name = name
        self.members = []
        self.vdom = "root"
        self.source_file = ""
        self.start_line = 0
        self.raw_config = ""

    def to_dict(self):
        return self.__dict__


class RouteModel:
    def __init__(self):
        self.id = "route_" + str(id(self))
        self.vdom = "root"
        self.type = "static"  # static, default, dynamic (bgp/ospf/rip), policy, sdwan
        self.destination = "0.0.0.0/0"
        self.gateway = "0.0.0.0"
        self.device = ""
        self.distance = 10
        self.priority = 0
        self.blackhole = False
        self.extra_info = {}  # routing protocol specific
        self.source_file = ""
        self.start_line = 0
        self.raw_config = ""

    def to_dict(self):
        return self.__dict__


class FirewallPolicyModel:
    def __init__(self, id_val):
        self.id = "policy_" + str(id_val)
        self.policy_id = id_val
        self.name = ""
        self.vdom = "root"
        self.srcintf = []
        self.dstintf = []
        self.srcaddr = []
        self.dstaddr = []
        self.service = []
        self.action = "deny"  # accept, deny
        self.nat = False
        self.ippool = ""
        self.ssl_inspection = False
        self.ips_sensor = ""
        self.av_profile = ""
        self.webfilter_profile = ""
        self.app_control = ""
        self.logtraffic = "all"  # all, utm, disable
        self.status = "enable"  # enable, disable
        self.schedule = "always"
        self.comments = ""
        self.order = 0
        self.source_file = ""
        self.start_line = 0
        self.raw_config = ""

    def to_dict(self):
        return self.__dict__


class VIPModel:
    def __init__(self, name):
        self.id = "vip_" + name.replace(" ", "_")
        self.name = name
        self.vdom = "root"
        self.extip = ""
        self.mappedip = ""
        self.extintf = "any"
        self.portforward = False
        self.extport = ""
        self.mappedport = ""
        self.source_file = ""
        self.start_line = 0
        self.raw_config = ""

    def to_dict(self):
        return self.__dict__


class IPPoolModel:
    def __init__(self, name):
        self.id = "ippool_" + name.replace(" ", "_")
        self.name = name
        self.vdom = "root"
        self.startip = ""
        self.endip = ""
        self.source_file = ""
        self.start_line = 0
        self.raw_config = ""

    def to_dict(self):
        return self.__dict__


class VPNModel:
    def __init__(self, name):
        self.id = "vpn_" + name.replace(" ", "_")
        self.name = name
        self.vdom = "root"
        self.type = "ipsec"  # ipsec, ssl-vpn
        # IPsec Phase 1/2
        self.remote_gw = ""
        self.interface = ""
        self.local_subnet = ""
        self.remote_subnet = ""
        # SSL-VPN parameters
        self.ssl_port = ""
        self.ssl_portal = ""
        self.ssl_address_range = ""
        self.source_file = ""
        self.start_line = 0
        self.raw_config = ""

    def to_dict(self):
        return self.__dict__


class InterVdomLinkModel:
    def __init__(self, name):
        self.id = "ivl_" + name.replace(" ", "_")
        self.name = name
        self.vdom_a = ""
        self.vdom_b = ""
        self.interface_a = ""
        self.interface_b = ""
        self.source_file = ""
        self.start_line = 0
        self.raw_config = ""

    def to_dict(self):
        return self.__dict__


class Finding:
    def __init__(self, category, severity, description, item_type="", item_name="", vdom="root"):
        self.id = "finding_" + str(id(self))
        self.category = category  # "routing", "policy", "interface", "vip", "vpn", "object"
        self.severity = severity  # "high", "medium", "low", "info"
        self.description = description
        self.item_type = item_type
        self.item_name = item_name
        self.vdom = vdom

    def to_dict(self):
        return self.__dict__
