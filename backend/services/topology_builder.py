from backend.parsers.fortigate_parser import parse_raw_config
from backend.parsers.global_parser import build_parsed_model
from backend.services.relationship_engine import RelationshipEngine
from backend.services.validation_engine import ValidationEngine

class TopologyBuilder:
    """
    Orchestrator to ingest raw configuration files and return a unified
    structured JSON object representing the network architecture, relationships, and validations.
    """
    @staticmethod
    def process_configs(global_file_data, vdoms_files_data=None):
        """
        global_file_data: {'filename': str, 'content': str}
        vdoms_files_data: list of {'filename': str, 'vdom_name': str, 'content': str}
        """
        # Parse global file
        global_content = global_file_data['content']
        global_fn = global_file_data['filename']

        global_node, global_lines = parse_raw_config(global_content, global_fn)

        # Build entire FortiGate data model
        device = build_parsed_model(
            global_node=global_node,
            global_lines=global_lines,
            global_filename=global_fn,
            vdom_files_data=vdoms_files_data
        )

        # Run coherence validations (Findings)
        ValidationEngine.validate_device(device)

        # Build visual network topology nodes & edges
        topology = RelationshipEngine.build_relationships(device)
        simple_topology = RelationshipEngine.build_simple_relationships(device)

        return device, topology, simple_topology
