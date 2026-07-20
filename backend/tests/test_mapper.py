import unittest
import os
import xml.etree.ElementTree as ET

from backend.parsers.fortigate_parser import parse_raw_config
from backend.parsers.global_parser import build_parsed_model
from backend.services.topology_builder import TopologyBuilder
from backend.services.relationship_engine import RelationshipEngine
from backend.services.validation_engine import ValidationEngine
from backend.services.drawio_exporter import DrawioExporter
from backend.services.report_exporter import ReportExporter

class TestFortiGateMapper(unittest.TestCase):
    def setUp(self):
        # Paths to sample files
        self.single_vdom_path = "samples/fictional_single_vdom.conf"
        self.three_vdoms_path = "samples/fictional_three_vdoms.conf"

    def test_single_vdom_parsing(self):
        """Tests reading and parsing a single fictional VDOM configuration."""
        self.assertTrue(os.path.exists(self.single_vdom_path))
        with open(self.single_vdom_path, "r", encoding="utf-8") as f:
            content = f.read()

        global_data = {"filename": "fictional_single_vdom.conf", "content": content}
        device, topology, simple_topology = TopologyBuilder.process_configs(global_data)

        # Verify General metadata
        self.assertEqual(device.hostname, "FortiGate-Fictif-Single")
        self.assertEqual(device.version, "v7.2.4")
        self.assertEqual(device.model, "FG-100F")
        self.assertEqual(device.serial_number, "FG100FTK23000123")

        # Verify Core elements parsed
        self.assertIn("root", device.vdoms)
        root_vdom = device.vdoms["root"]
        self.assertIn("port1", root_vdom.interfaces)
        self.assertIn("Zone-LAN", root_vdom.zones)
        self.assertIn("LAN-Subnet-192", root_vdom.address_objects)
        self.assertEqual(len(root_vdom.policies), 1)
        self.assertEqual(root_vdom.policies[0].policy_id, "1")
        self.assertEqual(root_vdom.policies[0].action, "accept")
        self.assertEqual(len(root_vdom.routes), 1)
        self.assertEqual(root_vdom.routes[0].gateway, "203.0.113.1")

    def test_three_vdoms_parsing(self):
        """Tests parsing a hierarchical 3-VDOM configuration file."""
        self.assertTrue(os.path.exists(self.three_vdoms_path))
        with open(self.three_vdoms_path, "r", encoding="utf-8") as f:
            content = f.read()

        global_data = {"filename": "fictional_three_vdoms.conf", "content": content}
        device, topology, simple_topology = TopologyBuilder.process_configs(global_data)

        # Verify General metadata
        self.assertEqual(device.hostname, "FortiGate-Fictif-3VDOM")
        self.assertEqual(device.model, "FG-200F")

        # Verify VDOM division
        self.assertIn("root", device.vdoms)
        self.assertIn("vdom_lan", device.vdoms)
        self.assertIn("vdom_dmz", device.vdoms)

        # Verify interfaces mapping inside correct VDOM
        self.assertIn("port1", device.vdoms["root"].interfaces)
        self.assertIn("port2", device.vdoms["vdom_lan"].interfaces)
        self.assertIn("port3", device.vdoms["vdom_dmz"].interfaces)

        # Verify VIP mapping
        vips = device.vdoms["vdom_dmz"].vips
        self.assertIn("VIP-WebServer", vips)
        self.assertEqual(vips["VIP-WebServer"].extip, "203.0.113.55")
        self.assertEqual(vips["VIP-WebServer"].mappedip, "172.16.50.10")

    def test_longest_prefix_match(self):
        """Tests that longest prefix matching for interfaces is correct."""
        interfaces = {
            "port1": type('obj', (object,), {"ip": "192.168.1.254", "mask": "255.255.255.0"}),
            "port2": type('obj', (object,), {"ip": "10.0.0.1", "mask": "255.255.0.0"})
        }
        # Exact match
        match = RelationshipEngine.find_matching_interface("192.168.1.0/24", interfaces)
        self.assertEqual(match, "port1")

        # Fallback out-of-range
        match_none = RelationshipEngine.find_matching_interface("172.16.0.0/16", interfaces)
        self.assertIsNone(match_none)

    def test_validation_findings(self):
        """Tests that validation engine detects anomalies like Any-to-Any or unused VIPs."""
        self.assertTrue(os.path.exists(self.three_vdoms_path))
        with open(self.three_vdoms_path, "r", encoding="utf-8") as f:
            content = f.read()

        global_data = {"filename": "fictional_three_vdoms.conf", "content": content}
        device, topology, simple_topology = TopologyBuilder.process_configs(global_data)

        # Check findings
        findings = device.findings
        self.assertTrue(len(findings) > 0)

        # There should be an info/low-level finding about missing routes or unused objects
        # e.g., missing VPN routing, empty zones or similar
        categories = [f.category for f in findings]
        self.assertTrue(len(categories) > 0)

    def test_drawio_export(self):
        """Tests XML structure and attributes in the Draw.io exporter."""
        self.assertTrue(os.path.exists(self.single_vdom_path))
        with open(self.single_vdom_path, "r", encoding="utf-8") as f:
            content = f.read()

        global_data = {"filename": "fictional_single_vdom.conf", "content": content}
        device, topology, simple_topology = TopologyBuilder.process_configs(global_data)

        xml_bytes = DrawioExporter.generate_drawio_xml(topology)
        self.assertTrue(len(xml_bytes) > 0)

        # Parse XML to verify valid root elements are generated
        root_element = ET.fromstring(xml_bytes)
        self.assertEqual(root_element.tag, "mxfile")
        diagram_element = root_element.find("diagram")
        self.assertIsNotNone(diagram_element)
        self.assertEqual(diagram_element.get("id"), "fortigate_layout")

    def test_report_export(self):
        """Tests report CSV inventory exporter generation."""
        self.assertTrue(os.path.exists(self.single_vdom_path))
        with open(self.single_vdom_path, "r", encoding="utf-8") as f:
            content = f.read()

        global_data = {"filename": "fictional_single_vdom.conf", "content": content}
        device, topology, simple_topology = TopologyBuilder.process_configs(global_data)

        csv_str = ReportExporter.generate_inventory_csv(device, "interfaces")
        self.assertIn("VDOM", csv_str)
        self.assertIn("port1", csv_str)
        self.assertIn("vlan10", csv_str)

    def test_simple_topology_generation(self):
        """Tests that build_simple_relationships successfully extracts correct VDOM & connection nodes."""
        self.assertTrue(os.path.exists(self.three_vdoms_path))
        with open(self.three_vdoms_path, "r", encoding="utf-8") as f:
            content = f.read()

        global_data = {"filename": "fictional_three_vdoms.conf", "content": content}
        device, topology, simple_topology = TopologyBuilder.process_configs(global_data)

        # Check nodes
        node_ids = [n["id"] for n in simple_topology["nodes"]]
        self.assertIn("node_internet", node_ids)
        self.assertIn("vdom_root", node_ids)
        self.assertIn("vdom_vdom_lan", node_ids)
        self.assertIn("vdom_vdom_dmz", node_ids)

        # Check edges
        edge_ids = [e["id"] for e in simple_topology["edges"]]
        # We should find at least one simple route link to Internet
        route_links = [e for e in simple_topology["edges"] if e["type"] == "route_link"]
        self.assertTrue(len(route_links) > 0)

if __name__ == "__main__":
    unittest.main()
