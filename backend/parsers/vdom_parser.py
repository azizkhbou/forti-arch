# Placeholder or delegate for vdom configuration parsing
from backend.parsers.global_parser import parse_node_into_device

def parse_vdom_config(root_node, all_lines, filename, device, target_vdom):
    parse_node_into_device(root_node, all_lines, filename, device, target_vdom=target_vdom)
