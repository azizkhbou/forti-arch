import os
import json
from flask import Flask, request, jsonify, send_from_directory, Response
from werkzeug.utils import secure_filename
from backend.services.topology_builder import TopologyBuilder
from backend.services.drawio_exporter import DrawioExporter
from backend.services.report_exporter import ReportExporter

app = Flask(__name__, static_folder="../frontend", static_url_path="")

# In-memory storage for the latest analyzed device and topology
# Keys: 'device' -> FortiGateModel, 'topology' -> topology dict, 'original_files' -> dict
LATEST_ANALYSIS = {
    "device": None,
    "topology": None,
    "original_files": {}
}

@app.route("/")
def index():
    return send_from_directory(app.static_folder, "index.html")

@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory(app.static_folder, path)

@app.route("/api/analyze", methods=["POST"])
def analyze_config():
    """
    Handles Mode A (single file) and Mode B (multiple files mapped to VDOMs) imports.
    """
    try:
        mode = request.form.get("mode", "A") # "A" or "B"
        anonymize = request.form.get("anonymize", "false") == "true"

        global_file = request.files.get("global_file")
        if not global_file:
            return jsonify({"error": "Fichier de configuration global manquant."}), 400

        global_filename = secure_filename(global_file.filename)
        global_content = global_file.read().decode("utf-8", errors="ignore")

        # Prepare data structured for builder
        global_data = {
            "filename": global_filename,
            "content": global_content
        }

        vdoms_data = []
        if mode == "B":
            # Read files for up to 3 VDOMs
            for i in range(1, 4):
                v_file = request.files.get(f"vdom_file_{i}")
                v_name = request.form.get(f"vdom_name_{i}")
                if v_file and v_name:
                    v_fn = secure_filename(v_file.filename)
                    v_content = v_file.read().decode("utf-8", errors="ignore")
                    vdoms_data.append({
                        "filename": v_fn,
                        "vdom_name": v_name,
                        "content": v_content
                    })

        # Optional: anonymize IP addresses
        if anonymize:
            global_data["content"] = anonymize_ip_addresses(global_data["content"])
            for vd in vdoms_data:
                vd["content"] = anonymize_ip_addresses(vd["content"])

        # Run topology processor
        device, topology, simple_topology = TopologyBuilder.process_configs(global_data, vdoms_data)

        # Save into memory
        LATEST_ANALYSIS["device"] = device
        LATEST_ANALYSIS["topology"] = topology
        LATEST_ANALYSIS["simple_topology"] = simple_topology

        # Keep track of line sources for "View Source" functionality
        LATEST_ANALYSIS["original_files"] = {
            global_filename: global_content.splitlines()
        }
        for vd in vdoms_data:
            LATEST_ANALYSIS["original_files"][vd["filename"]] = vd["content"].splitlines()

        # Build response
        return jsonify({
            "success": True,
            "device": device.to_dict(),
            "topology": topology,
            "simple_topology": simple_topology
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Erreur lors de l'analyse : {str(e)}"}), 500


@app.route("/api/source-code", methods=["POST"])
def get_source_code():
    """
    Returns the raw block of config from the uploaded files given filename, start_line, and end_line.
    """
    req_data = request.json or {}
    filename = req_data.get("filename")
    start = req_data.get("start_line", 0)
    end = req_data.get("end_line", 0)

    if not filename or filename not in LATEST_ANALYSIS["original_files"]:
        return jsonify({"code": "Fichier source indisponible ou non chargé."})

    lines = LATEST_ANALYSIS["original_files"][filename]
    # adjusting index (lines are 1-indexed)
    start_idx = max(0, start - 1)
    end_idx = min(len(lines), end)

    selected_lines = lines[start_idx:end_idx]
    return jsonify({
        "code": "\n".join(selected_lines),
        "filename": filename,
        "start": start,
        "end": end
    })


@app.route("/api/export/drawio", methods=["POST"])
def export_drawio():
    """
    Generates and downloads a .drawio editable XML.
    """
    if not LATEST_ANALYSIS["topology"]:
        return jsonify({"error": "Aucune analyse disponible pour l'export."}), 400

    # Draw.io layout could have customized node coordinates sent by front-end
    req_data = request.json or {}
    coordinates = req_data.get("coordinates") # mapping of node_id -> {x, y, width, height}

    xml_data = DrawioExporter.generate_drawio_xml(LATEST_ANALYSIS["topology"], coordinates)

    # Custom filename
    fn = "architecture_fortigate.drawio"
    if LATEST_ANALYSIS["device"]:
        fn = f"architecture_{LATEST_ANALYSIS['device'].hostname}.drawio"

    return Response(
        xml_data,
        mimetype="application/xml",
        headers={"Content-disposition": f"attachment; filename={fn}"}
    )


@app.route("/api/export/csv", methods=["GET"])
def export_csv():
    """
    Exports specified inventory as CSV.
    """
    if not LATEST_ANALYSIS["device"]:
        return jsonify({"error": "Aucune analyse disponible pour l'export."}), 400

    item_type = request.args.get("type", "interfaces")
    csv_data = ReportExporter.generate_inventory_csv(LATEST_ANALYSIS["device"], item_type)

    fn = f"inventaire_{item_type}.csv"
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": f"attachment; filename={fn}"}
    )


@app.route("/api/export/json", methods=["GET"])
def export_json():
    """
    Exports full extracted JSON.
    """
    if not LATEST_ANALYSIS["device"]:
        return jsonify({"error": "Aucune analyse de configuration disponible."}), 400

    data = {
        "device": LATEST_ANALYSIS["device"].to_dict(),
        "topology": LATEST_ANALYSIS["topology"]
    }
    return jsonify(data)


@app.route("/api/reset", methods=["POST"])
def reset_analysis():
    """
    Resets analyzed data from memory to guarantee privacy.
    """
    LATEST_ANALYSIS["device"] = None
    LATEST_ANALYSIS["topology"] = None
    LATEST_ANALYSIS["original_files"] = {}
    return jsonify({"success": True, "message": "Données d'analyse réinitialisées avec succès."})


def anonymize_ip_addresses(content):
    """
    Anonymizes IP addresses in the text config file by replacing
    private/public patterns with standardized dummy subnets.
    """
    import re
    # We will match IP addresses like set ip 192.168.1.1 255.255.255.0
    # Simple regex to swap 10.x.x.x -> 10.99.x.x, 192.168.x.x -> 192.168.99.x
    def replace_ip(match):
        ip = match.group(0)
        # Skip subnet masks
        if ip in ["255.255.255.0", "255.255.255.255", "255.255.0.0", "255.0.0.0"]:
            return ip
        # Simple mapping
        if ip.startswith("192.168."):
            parts = ip.split(".")
            return f"192.168.99.{parts[3]}"
        elif ip.startswith("10."):
            parts = ip.split(".")
            return f"10.99.{parts[2]}.{parts[3]}"
        elif ip.startswith("172.16."):
            parts = ip.split(".")
            return f"172.99.{parts[2]}.{parts[3]}"
        # If it is any other public IP, map to a test IP
        return "198.51.100.22"

    # Match raw IP octets
    anonymized = re.sub(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', replace_ip, content)
    return anonymized


if __name__ == "__main__":
    # Standard local hosting
    app.run(host="127.0.0.1", port=5000, debug=True)
