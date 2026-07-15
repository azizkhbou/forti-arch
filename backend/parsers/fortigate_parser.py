import re

class ConfigNode:
    def __init__(self, type_name, name=None, parent=None, start_line=0, file_name=""):
        self.type_name = type_name  # 'global', 'config', 'edit'
        self.name = name
        self.parent = parent
        self.start_line = start_line
        self.end_line = start_line
        self.file_name = file_name
        self.settings = {}  # key -> { 'value': value_str, 'line': line_num, 'raw': raw_str }
        self.children = []  # list of ConfigNode

    def add_child(self, child):
        self.children.append(child)

    def set_setting(self, key, value, line, raw):
        # Mask sensitive keys
        sensitive_keywords = ['passwd', 'password', 'pre-shared-key', 'secret', 'private-key', 'passphrase', 'key']
        if any(kw in key.lower() for kw in sensitive_keywords):
            value = "[MASKED]"
            raw = re.sub(r'(set\s+\S+\s+).*', r'\1"[MASKED]"', raw)
        self.settings[key] = {
            'value': value,
            'line': line,
            'raw': raw
        }

    def get_setting(self, key, default=None):
        if key in self.settings:
            return self.settings[key]['value']
        return default

    def get_setting_raw(self, key):
        if key in self.settings:
            return self.settings[key]['raw']
        return ""

    def get_block_lines(self, all_lines):
        """Returns the raw lines of this block for trace view."""
        if not all_lines or self.start_line < 1 or self.end_line < 1:
            return ""
        # 0-indexed adjustment
        start = max(0, self.start_line - 1)
        end = min(len(all_lines), self.end_line)
        return "\n".join(all_lines[start:end])

    def find_child(self, type_name, name=None):
        for child in self.children:
            if child.type_name == type_name:
                if name is None or child.name == name:
                    return child
        return None

    def find_all_children(self, type_name):
        return [child for child in self.children if child.type_name == type_name]

    def to_dict(self):
        return {
            'type_name': self.type_name,
            'name': self.name,
            'start_line': self.start_line,
            'end_line': self.end_line,
            'file_name': self.file_name,
            'settings': self.settings,
            'children': [c.to_dict() for c in self.children]
        }


def parse_raw_config(file_content, file_name="config.conf"):
    """
    Parses FortiGate CLI configuration string into a ConfigNode tree.
    Tracks line numbers, file names, and masks passwords/keys.
    """
    lines = file_content.splitlines()
    root = ConfigNode(type_name="root", name="root", start_line=1, file_name=file_name)

    current = root

    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # config <section>
        config_match = re.match(r"^config\s+(.+)$", stripped)
        if config_match:
            sec_name = config_match.group(1).strip().strip('"')
            node = ConfigNode(type_name="config", name=sec_name, parent=current, start_line=i, file_name=file_name)
            current.add_child(node)
            current = node
            continue

        # edit <identifier>
        edit_match = re.match(r"^edit\s+(.+)$", stripped)
        if edit_match:
            item_name = edit_match.group(1).strip().strip('"')
            node = ConfigNode(type_name="edit", name=item_name, parent=current, start_line=i, file_name=file_name)
            current.add_child(node)
            current = node
            continue

        # next
        if stripped == "next":
            current.end_line = i
            if current.parent:
                current = current.parent
            continue

        # end
        if stripped == "end":
            current.end_line = i
            if current.parent:
                current = current.parent
            continue

        # set <key> <val>
        set_match = re.match(r"^set\s+(\S+)\s*(.*)$", stripped)
        if set_match:
            key = set_match.group(1)
            val = set_match.group(2).strip()
            # Remove bounding quotes if present
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]
            elif val.startswith("'") and val.endswith("'"):
                val = val[1:-1]
            current.set_setting(key, val, i, line)
            continue

        # unset <key>
        unset_match = re.match(r"^unset\s+(\S+)$", stripped)
        if unset_match:
            key = unset_match.group(1)
            current.set_setting(key, "unset", i, line)
            continue

    # Set root end_line
    root.end_line = len(lines)
    return root, lines
