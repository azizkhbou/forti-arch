class FortiGateApp {
    constructor() {
        this.currentMode = 'A'; // A or B
        this.selectedFiles = {
            'global': null,
            'b-global': null,
            'vdom-1': null,
            'vdom-2': null,
            'vdom-3': null
        };

        this.analysisData = null; // latest analysis results
        this.cy = null; // cytoscape instance
        this.activeLayerSettings = {
            physical: true,
            logical: true,
            vpn: true,
            vip: true,
            flows: true
        };
        this.currentInventory = 'interfaces';
        this.ultraSimpleMode = false;
    }

    toggleUltraSimple(isChecked) {
        this.ultraSimpleMode = isChecked;

        // Hide/Show visual layers panel elements when simple mode is active
        const layers = ['physical', 'logical', 'vpn', 'vip'];
        layers.forEach(layer => {
            const labelEl = document.getElementById(`layer-${layer}-label`);
            if (labelEl) {
                labelEl.style.opacity = isChecked ? '0.4' : '1.0';
                labelEl.style.pointerEvents = isChecked ? 'none' : 'auto';
            }
        });

        // Apply or reset graph view
        this.renderNetworkGraph();
    }

    switchMode(mode) {
        this.currentMode = mode;
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        if (mode === 'A') {
            document.getElementById('btn-mode-a').classList.add('active');
            document.getElementById('mode-a-section').style.display = 'block';
            document.getElementById('mode-b-section').style.display = 'none';
        } else {
            document.getElementById('btn-mode-b').classList.add('active');
            document.getElementById('mode-a-section').style.display = 'none';
            document.getElementById('mode-b-section').style.display = 'block';
        }
    }

    handleFileSelected(inputElement, fileKey) {
        const file = inputElement.files[0];
        if (file) {
            this.selectedFiles[fileKey] = file;
            const listEl = document.getElementById(`file-list-${fileKey}`) || document.createElement('div');
            listEl.id = `file-list-${fileKey}`;
            listEl.className = 'file-list';
            listEl.style.display = 'block';
            listEl.innerHTML = `<strong>Chargé :</strong> ${file.name} (${(file.size / 1024).toFixed(1)} KB)`;

            // Insert file list block if needed
            if (!document.getElementById(`file-list-${fileKey}`)) {
                inputElement.parentNode.appendChild(listEl);
            }
        }
    }

    showImportScreen() {
        document.getElementById('import-screen').style.display = 'flex';
        document.getElementById('main-screen').style.display = 'none';
    }

    async triggerAnalysis() {
        const formData = new FormData();
        formData.append('mode', this.currentMode);
        formData.append('anonymize', document.getElementById('chk-anonymize').checked);

        if (this.currentMode === 'A') {
            if (!this.selectedFiles['global']) {
                alert("Veuillez sélectionner le fichier complet FortiGate.");
                return;
            }
            formData.append('global_file', this.selectedFiles['global']);
        } else {
            if (!this.selectedFiles['b-global']) {
                alert("Veuillez sélectionner le fichier de configuration Global.");
                return;
            }
            formData.append('global_file', this.selectedFiles['b-global']);

            // VDOM 1
            const v1_name = document.getElementById('vdom-name-1').value;
            if (this.selectedFiles['vdom-1']) {
                formData.append('vdom_file_1', this.selectedFiles['vdom-1']);
                formData.append('vdom_name_1', v1_name);
            }
            // VDOM 2
            const v2_name = document.getElementById('vdom-name-2').value;
            if (this.selectedFiles['vdom-2']) {
                formData.append('vdom_file_2', this.selectedFiles['vdom-2']);
                formData.append('vdom_name_2', v2_name);
            }
            // VDOM 3
            const v3_name = document.getElementById('vdom-name-3').value;
            if (this.selectedFiles['vdom-3']) {
                formData.append('vdom_file_3', this.selectedFiles['vdom-3']);
                formData.append('vdom_name_3', v3_name);
            }
        }

        // Send to backend
        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                body: formData
            });
            const data = await response.json();

            if (data.error) {
                alert(data.error);
                return;
            }

            this.analysisData = data;

            // Transition to dashboard
            document.getElementById('import-screen').style.display = 'none';
            document.getElementById('main-screen').style.display = 'flex';

            // Populate dashboard metadata
            this.populateMetadata();

            // Render Graph
            this.renderNetworkGraph();

            // Populate Filters VDOM
            this.populateVdomFilters();

            // Switch to initial Inventory
            this.switchInventory(this.currentInventory);

        } catch (error) {
            console.error(error);
            alert("Une erreur de communication est survenue lors de l'analyse.");
        }
    }

    populateMetadata() {
        const dev = this.analysisData.device;
        document.getElementById('syn-hostname').textContent = dev.hostname || '-';
        document.getElementById('syn-model').textContent = dev.model || '-';
        document.getElementById('syn-version').textContent = dev.version || '-';
        document.getElementById('syn-serial').textContent = dev.serial_number || '-';

        // Quality side-panel
        const qr = dev.quality_report;
        const qPanel = document.getElementById('quality-report-sidebar');
        qPanel.innerHTML = `
            <p><strong>Lignes analysées :</strong> ${qr.lines_analyzed}</p>
            <p><strong>VDOMs détectés :</strong> ${qr.vdoms_detected}</p>
            <p><strong>Interfaces :</strong> ${qr.interfaces}</p>
            <p><strong>Zones :</strong> ${qr.zones}</p>
            <p><strong>VLANs :</strong> ${qr.vlans}</p>
            <p><strong>Routes :</strong> ${qr.routes}</p>
            <p><strong>Politiques Firewall :</strong> ${qr.policies}</p>
            <p><strong>VIPs :</strong> ${qr.vips}</p>
            <p><strong>VPNs :</strong> ${qr.vpns}</p>
            <p><strong>Objets Réseau :</strong> ${qr.objects}</p>
            <div style="margin-top: 10px; background-color: #EDF2F7; padding: 10px; border-radius: 4px; border: 1px solid #CBD5E0;">
                <strong>Niveau de Complétude :</strong> ${qr.completeness}%
                <div style="width: 100%; height: 8px; background-color: #E2E8F0; border-radius: 4px; overflow: hidden; margin-top: 5px;">
                    <div style="width: ${qr.completeness}%; height: 100%; background-color: var(--primary-color);"></div>
                </div>
            </div>
        `;

        // Update anomalies count
        document.getElementById('anomalies-count').textContent = dev.findings ? dev.findings.length : 0;
    }

    populateVdomFilters() {
        const select = document.getElementById('filter-vdom');
        // Clear except first "Tous"
        select.innerHTML = '<option value="all">Tous les VDOMs</option>';

        const vdomNames = Object.keys(this.analysisData.device.vdoms);
        vdomNames.forEach(name => {
            const opt = document.createElement('option');
            opt.value = name;
            opt.textContent = name;
            select.appendChild(opt);
        });
    }

    renderNetworkGraph() {
        const top = this.ultraSimpleMode ? this.analysisData.simple_topology : this.analysisData.topology;

        // Assemble cytoscape elements (nodes & edges)
        const cyElements = [];

        // Add nodes
        top.nodes.forEach(node => {
            const cyNode = {
                data: {
                    id: node.id,
                    label: node.label,
                    type: node.type,
                    parent: this.ultraSimpleMode ? undefined : (node.parent || undefined),
                    details: node.details,
                    vdom: node.vdom || 'root'
                }
            };
            cyElements.push(cyNode);
        });

        // Add edges
        top.edges.forEach(edge => {
            const cyEdge = {
                data: {
                    id: edge.id,
                    source: edge.source,
                    target: edge.target,
                    label: edge.label,
                    type: edge.type,
                    dashed: edge.dashed || false,
                    details: edge.details
                }
            };
            cyElements.push(cyEdge);
        });

        // Initialize cytoscape instance with an intuitive draw.io stylesheet
        this.cy = cytoscape({
            container: document.getElementById('cy'),
            elements: cyElements,
            style: [
                {
                    selector: 'node',
                    style: {
                        'background-color': '#FFFFFF',
                        'border-width': '2px',
                        'border-color': '#1A202C',
                        'label': 'data(label)',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '10px',
                        'color': '#2D3748',
                        'shape': 'round-rectangle',
                        'width': '100px',
                        'height': '50px',
                        'text-wrap': 'wrap'
                    }
                },
                {
                    selector: 'node[type="firewall"]',
                    style: {
                        'background-color': '#FFF5F5',
                        'border-color': '#C1272D',
                        'border-width': '3px',
                        'font-weight': 'bold',
                        'width': '130px',
                        'height': '65px'
                    }
                },
                {
                    selector: 'node[type="vdom"]',
                    style: {
                        'background-color': this.ultraSimpleMode ? '#1A365D' : 'rgba(235, 248, 255, 0.4)',
                        'border-color': '#3182CE',
                        'border-style': 'solid',
                        'border-width': '2px',
                        'text-valign': this.ultraSimpleMode ? 'center' : 'top',
                        'text-halign': 'center',
                        'font-size': this.ultraSimpleMode ? '14px' : '12px',
                        'font-weight': 'bold',
                        'color': this.ultraSimpleMode ? '#FFFFFF' : '#2D3748',
                        'width': this.ultraSimpleMode ? '160px' : '100px',
                        'height': this.ultraSimpleMode ? '60px' : '50px'
                    }
                },
                {
                    selector: 'node[type="zone"]',
                    style: {
                        'background-color': 'rgba(254, 252, 191, 0.2)',
                        'border-color': '#ECC94B',
                        'border-style': 'dashed',
                        'border-width': '2.5px',
                        'text-valign': 'top',
                        'text-halign': 'center',
                        'font-size': '11px'
                    }
                },
                {
                    selector: 'node[type="interface"]',
                    style: {
                        'background-color': '#F0FFF4',
                        'border-color': '#38A169',
                        'width': '85px',
                        'height': '40px'
                    }
                },
                {
                    selector: 'node[type="subnet"]',
                    style: {
                        'background-color': '#FAF5FF',
                        'border-color': '#805AD5',
                        'shape': 'hexagon',
                        'width': '85px',
                        'height': '50px'
                    }
                },
                {
                    selector: 'node[type="internet"]',
                    style: {
                        'background-color': '#EBF8FF',
                        'border-color': '#3182CE',
                        'shape': 'ellipse',
                        'width': '80px',
                        'height': '80px',
                        'font-weight': 'bold'
                    }
                },
                {
                    selector: 'node[type="vip"]',
                    style: {
                        'background-color': '#FFF5F5',
                        'border-color': '#E53E3E',
                        'shape': 'diamond',
                        'width': '80px',
                        'height': '80px'
                    }
                },
                {
                    selector: 'node[type="vpn"]',
                    style: {
                        'background-color': '#FFFFF0',
                        'border-color': '#D69E2E',
                        'width': '85px',
                        'height': '50px'
                    }
                },
                {
                    selector: 'node[type="server"]',
                    style: {
                        'background-color': '#EDF2F7',
                        'border-color': '#4A5568',
                        'shape': 'round-rectangle',
                        'width': '80px',
                        'height': '55px'
                    }
                },
                {
                    selector: 'edge',
                    style: {
                        'width': 2,
                        'line-color': '#4A5568',
                        'target-arrow-color': '#4A5568',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'taxi', // orthogonal/taxi lines
                        'label': 'data(label)',
                        'font-size': '8px',
                        'color': '#1A202C',
                        'text-background-opacity': 1,
                        'text-background-color': '#FFFFFF',
                        'text-background-padding': '2px',
                        'text-background-shape': 'round-rectangle'
                    }
                },
                {
                    selector: 'edge[dashed=true]',
                    style: {
                        'line-style': 'dashed'
                    }
                },
                {
                    selector: 'edge[type="wan_link"]',
                    style: {
                        'line-color': '#3182CE',
                        'target-arrow-color': '#3182CE',
                        'width': 3
                    }
                },
                {
                    selector: 'edge[type="policy_flow"]',
                    style: {
                        'line-color': '#48BB78',
                        'target-arrow-color': '#48BB78',
                        'width': 2.5
                    }
                },
                {
                    selector: 'edge[type="inter_vdom_link"]',
                    style: {
                        'line-color': '#E53E3E',
                        'target-arrow-color': '#E53E3E',
                        'width': 3
                    }
                },
                {
                    selector: 'edge[type="route_link"]',
                    style: {
                        'line-color': '#D69E2E',
                        'target-arrow-color': '#D69E2E',
                        'line-style': 'dashed',
                        'width': 2.5
                    }
                }
            ],
            layout: {
                name: 'preset'
            }
        });

        // On selection click
        this.cy.on('tap', 'node, edge', (evt) => {
            const target = evt.target;
            this.showProperties(target);
        });

        // Trigger our beautiful, clean hierarchical structure
        this.reorganizeLayout();
    }

    reorganizeLayout() {
        if (!this.cy) return;

        // If simple mode, arrange VDOMs and Internet elegantly
        if (this.ultraSimpleMode) {
            const internetNode = this.cy.getElementById('node_internet');
            if (internetNode.length > 0) {
                internetNode.position({ x: 600, y: 100 });
            }

            const vdoms = this.cy.nodes('[type="vdom"]');
            const vdomCount = vdoms.length;
            const startX = 600 - ((vdomCount - 1) * 300) / 2;
            const vdomY = 350;

            vdoms.forEach((vdomNode, idx) => {
                vdomNode.position({ x: startX + (idx * 300), y: vdomY });
            });

            this.cy.fit();
            return;
        }

        // Elegant layout algorithm:
        // Internet is always at top center: {x: 600, y: 50}
        // Firewall FortiGate centered at: {x: 600, y: 150}
        // VDOMs side by side under the Firewall

        const vdoms = this.cy.nodes('[type="vdom"]');
        const vdomCount = vdoms.length;

        // Define center positions dynamically
        const internetNode = this.cy.getElementById('node_internet');
        if (internetNode.length > 0) {
            internetNode.position({ x: 600, y: 50 });
        }

        const fgtNode = this.cy.getElementById('node_fortigate');
        if (fgtNode.length > 0) {
            fgtNode.position({ x: 600, y: 150 });
        }

        const startX = 600 - ((vdomCount - 1) * 450) / 2;
        const vdomY = 320;

        vdoms.forEach((vdomNode, idx) => {
            const vdomX = startX + (idx * 450);
            vdomNode.position({ x: vdomX, y: vdomY });

            const vdomId = vdomNode.id();

            // Layout children within this VDOM container in structured columns:
            // LAN (Users, Left side of VDOM box)
            // DMZ / Servers / VIPs (Right side of VDOM box)
            // Transit / VPNs (Center of VDOM box)

            const zones = this.cy.nodes(`[type="zone"][parent="${vdomId}"]`);
            const interfaces = this.cy.nodes(`[type="interface"][parent="${vdomId}"]`);
            const subnets = this.cy.nodes(`[type="subnet"][parent="${vdomId}"]`);
            const vips = this.cy.nodes(`[type="vip"][parent="${vdomId}"]`);
            const vpns = this.cy.nodes(`[type="vpn"][parent="${vdomId}"]`);
            const servers = this.cy.nodes(`[type="server"][parent="${vdomId}"]`);

            // 1. LAN column (Left, Offset x: -220)
            let lanY = vdomY + 80;
            zones.forEach(zone => {
                const zName = zone.data('label').toLowerCase();
                if (zName.includes('lan') || zName.includes('internal') || zName.includes('usr')) {
                    zone.position({ x: vdomX - 220, y: lanY });

                    // Position interfaces inside LAN zone
                    const zoneId = zone.id();
                    const zoneIntfs = this.cy.nodes(`[type="interface"][parent="${zoneId}"]`);
                    zoneIntfs.forEach((zi, zidx) => {
                        zi.position({ x: vdomX - 220, y: lanY + 60 + (zidx * 60) });
                    });
                    lanY += 180 + (zoneIntfs.length * 60);
                }
            });

            // LAN interfaces not inside zones
            interfaces.forEach(intf => {
                const label = intf.data('label').toLowerCase();
                const parent = intf.data('parent');
                if (parent === vdomId && (label.includes('lan') || label.includes('port2'))) {
                    intf.position({ x: vdomX - 220, y: lanY });
                    lanY += 80;
                }
            });

            // LAN subnets
            subnets.forEach(sub => {
                const label = sub.data('label').toLowerCase();
                if (label.includes('lan') || label.includes('10.')) {
                    sub.position({ x: vdomX - 220, y: lanY });
                    lanY += 80;
                }
            });

            // 2. DMZ & Servers column (Right, Offset x: 220)
            let dmzY = vdomY + 80;
            zones.forEach(zone => {
                const zName = zone.data('label').toLowerCase();
                if (zName.includes('dmz') || zName.includes('srv') || zName.includes('server')) {
                    zone.position({ x: vdomX + 220, y: dmzY });

                    const zoneId = zone.id();
                    const zoneIntfs = this.cy.nodes(`[type="interface"][parent="${zoneId}"]`);
                    zoneIntfs.forEach((zi, zidx) => {
                        zi.position({ x: vdomX + 220, y: dmzY + 60 + (zidx * 60) });
                    });
                    dmzY += 180 + (zoneIntfs.length * 60);
                }
            });

            interfaces.forEach(intf => {
                const label = intf.data('label').toLowerCase();
                const parent = intf.data('parent');
                if (parent === vdomId && (label.includes('dmz') || label.includes('srv') || label.includes('port3'))) {
                    intf.position({ x: vdomX + 220, y: dmzY });
                    dmzY += 80;
                }
            });

            vips.forEach(vip => {
                vip.position({ x: vdomX + 220, y: dmzY });
                dmzY += 90;
            });

            servers.forEach(srv => {
                srv.position({ x: vdomX + 220, y: dmzY });
                dmzY += 80;
            });

            // 3. MPLS / WAN & Transit column (Center, Offset x: 0)
            let transitY = vdomY + 80;

            // Map MPLS zones specifically to avoid any overlapping
            zones.forEach(zone => {
                const zName = zone.data('label').toLowerCase();
                if (zName.includes('mpls') || zName.includes('wan') || zName.includes('transit')) {
                    zone.position({ x: vdomX, y: transitY });

                    const zoneId = zone.id();
                    const zoneIntfs = this.cy.nodes(`[type="interface"][parent="${zoneId}"]`);
                    zoneIntfs.forEach((zi, zidx) => {
                        zi.position({ x: vdomX, y: transitY + 60 + (zidx * 60) });
                    });
                    transitY += 180 + (zoneIntfs.length * 60);
                }
            });

            interfaces.forEach(intf => {
                const label = intf.data('label').toLowerCase();
                const parent = intf.data('parent');
                if (parent === vdomId && (label.includes('wan') || label.includes('port1') || label.includes('vlink') || label.includes('mpls'))) {
                    // Avoid overlapping if already positioned inside zone
                    if (intf.data('parent') && intf.data('parent').startsWith('zone_')) {
                        return;
                    }
                    intf.position({ x: vdomX, y: transitY });
                    transitY += 80;
                }
            });

            vpns.forEach(vpn => {
                vpn.position({ x: vdomX, y: transitY });
                transitY += 80;
            });

            subnets.forEach(sub => {
                const label = sub.data('label').toLowerCase();
                if (label.includes('any') || label.includes('0.0.0.0')) {
                    sub.position({ x: vdomX, y: transitY });
                    transitY += 80;
                }
            });
        });

        // Remote sites placed beautifully on bottom sides
        const remoteSites = this.cy.nodes('[type="remote_site"]');
        remoteSites.forEach((site, sIdx) => {
            site.position({ x: sIdx % 2 === 0 ? 100 : 1100, y: 650 + (Math.floor(sIdx / 2) * 90) });
        });

        this.cy.fit();
    }

    zoomIn() { this.cy && this.cy.zoom(this.cy.zoom() + 0.1); }
    zoomOut() { this.cy && this.cy.zoom(this.cy.zoom() - 0.1); }
    fitToScreen() { this.cy && this.cy.fit(); }

    toggleLayer(layerKey, isChecked) {
        this.activeLayerSettings[layerKey] = isChecked;
        this.applyFilters();
    }

    applyFilters() {
        if (!this.cy) return;

        const focusVdom = document.getElementById('filter-vdom').value;
        const policyFilter = document.getElementById('filter-policies').value;
        const hideUnused = document.getElementById('chk-hide-unused').checked;

        this.cy.batch(() => {
            // Restore visibility of all elements
            this.cy.elements().removeClass('filtered-out');
            this.cy.elements().show();

            // Under Ultra-Simple mode, hide interface, zone, vpn, vip and ignore toggle controls
            if (this.ultraSimpleMode) {
                this.cy.elements('node[type="interface"], node[type="zone"], node[type="vpn"], node[type="vip"], node[type="server"], node[type="subnet"], node[type="remote_site"]').hide();
                // Also hide irrelevant edges
                this.cy.elements('edge[type="wan_link"], edge[type="vpn_tunnel"], edge[type="vip_link"], edge[type="subnet_link"], edge[type="subnet_link_deduced"]').hide();

                // Show policy flows and route links
                if (!this.activeLayerSettings.flows) {
                    this.cy.elements('edge[type="policy_flow"]').hide();
                }
                return;
            }

            // Layer hides
            if (!this.activeLayerSettings.physical) {
                this.cy.elements('node[type="interface"]').hide();
            }
            if (!this.activeLayerSettings.logical) {
                this.cy.elements('node[type="vdom"], node[type="zone"]').hide();
            }
            if (!this.activeLayerSettings.vpn) {
                this.cy.elements('node[type="vpn"], edge[type="vpn_tunnel"]').hide();
            }
            if (!this.activeLayerSettings.vip) {
                this.cy.elements('node[type="vip"], [type="vip_link"]').hide();
            }
            if (!this.activeLayerSettings.flows) {
                this.cy.elements('edge[type="policy_flow"]').hide();
            }

            // VDOM focus
            if (focusVdom !== 'all') {
                this.cy.nodes().forEach(node => {
                    const nodeVdom = node.data('vdom');
                    if (nodeVdom && nodeVdom !== 'global' && nodeVdom !== focusVdom) {
                        node.hide();
                    }
                });
            }

            // Policy Filters
            if (policyFilter !== 'all') {
                this.cy.edges('[type="policy_flow"]').forEach(edge => {
                    const details = edge.data('details');
                    if (details) {
                        if (policyFilter === 'active' && details.status === 'disable') {
                            edge.hide();
                        } else if (policyFilter === 'deny' && details.action !== 'deny') {
                            edge.hide();
                        } else if (policyFilter === 'nat' && !details.nat) {
                            edge.hide();
                        }
                    }
                });
            }

            // Hide unused
            if (hideUnused) {
                // If a subnet has no connected edges, hide it
                this.cy.nodes('[type="subnet"]').forEach(node => {
                    if (node.degree() === 0) {
                        node.hide();
                    }
                });
            }
        });
    }

    addCustomNode() {
        const type = document.getElementById('add-node-type').value;
        const label = document.getElementById('add-node-label').value;

        if (!label) {
            alert("Veuillez saisir un nom pour l'équipement.");
            return;
        }

        if (!this.cy) {
            alert("Aucun diagramme actif.");
            return;
        }

        // Add node directly to center of the current screen view
        const center = this.cy.extent();
        const centerX = center.x1 + (center.x2 - center.x1) / 2;
        const centerY = center.y1 + (center.y2 - center.y1) / 2;

        const newNodeId = `manual_node_${Date.now()}`;
        this.cy.add({
            group: 'nodes',
            data: {
                id: newNodeId,
                label: label,
                type: type,
                vdom: 'root',
                details: {
                    description: "Équipement ajouté manuellement par l'utilisateur",
                    status: 'up'
                }
            },
            position: { x: centerX, y: centerY }
        });

        // Clear input
        document.getElementById('add-node-label').value = '';
    }

    showProperties(element) {
        const panel = document.getElementById('properties-panel');
        const data = element.data();

        if (!data) return;

        let htmlContent = `<h3 style="margin-top:0; color:var(--primary-color);">${data.label || data.id}</h3>`;
        htmlContent += `<p><strong>Type :</strong> ${data.type || 'Liaison'}</p>`;

        if (data.vdom) {
            htmlContent += `<p><strong>VDOM :</strong> ${data.vdom}</p>`;
        }

        if (data.details) {
            htmlContent += `<h4 style="margin: 10px 0 5px; border-bottom: 1px solid #CBD5E0;">Détails Techniques</h4>`;

            // Check if it's a policy flow to show styled security profiles nicely
            if (data.type === 'policy_flow') {
                const det = data.details;
                htmlContent += `
                    <div style="background-color: #F7FAFC; padding: 10px; border-radius: 6px; border: 1px solid #E2E8F0; margin-bottom: 10px;">
                        <p style="margin: 3px 0;"><strong>ID de Règle :</strong> <span class="badge" style="background:#4A5568;">${det.policy_id}</span></p>
                        <p style="margin: 3px 0;"><strong>Nom :</strong> ${det.name || '-'}</p>
                        <p style="margin: 3px 0;"><strong>Action :</strong> <span class="badge" style="background:${det.action === 'accept' ? '#38A169' : '#E53E3E'}">${det.action.toUpperCase()}</span></p>
                        <p style="margin: 3px 0;"><strong>NAT :</strong> ${det.nat ? 'Activé' : 'Désactivé'}</p>
                        <p style="margin: 3px 0;"><strong>Source Addr :</strong> ${Array.isArray(det.srcaddr) ? det.srcaddr.join(', ') : (det.srcaddr || '-')}</p>
                        <p style="margin: 3px 0;"><strong>Dest Addr :</strong> ${Array.isArray(det.dstaddr) ? det.dstaddr.join(', ') : (det.dstaddr || '-')}</p>
                        <p style="margin: 3px 0;"><strong>Services :</strong> ${Array.isArray(det.services) ? det.services.join(', ') : (det.services || '-')}</p>
                    </div>

                    <h4 style="margin: 10px 0 5px; border-bottom: 1px solid #CBD5E0; color: #2B6CB0;">Profils de Sécurité</h4>
                    <div style="display: flex; flex-direction: column; gap: 6px; margin-top: 8px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; background: ${det.av_profile ? '#C6F6D5' : '#EDF2F7'}; border-radius: 4px; border: 1px solid ${det.av_profile ? '#38A169' : '#CBD5E0'};">
                            <span style="font-weight: bold; color: ${det.av_profile ? '#22543D' : '#4A5568'};">Antivirus</span>
                            <span style="font-size: 0.8rem; font-style: italic;">${det.av_profile || 'Désactivé'}</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; background: ${det.ips_sensor ? '#C6F6D5' : '#EDF2F7'}; border-radius: 4px; border: 1px solid ${det.ips_sensor ? '#38A169' : '#CBD5E0'};">
                            <span style="font-weight: bold; color: ${det.ips_sensor ? '#22543D' : '#4A5568'};">IPS (Intrusion Prevention)</span>
                            <span style="font-size: 0.8rem; font-style: italic;">${det.ips_sensor || 'Désactivé'}</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; background: ${det.app_control ? '#C6F6D5' : '#EDF2F7'}; border-radius: 4px; border: 1px solid ${det.app_control ? '#38A169' : '#CBD5E0'};">
                            <span style="font-weight: bold; color: ${det.app_control ? '#22543D' : '#4A5568'};">Application Control</span>
                            <span style="font-size: 0.8rem; font-style: italic;">${det.app_control || 'Désactivé'}</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; background: ${det.webfilter_profile ? '#C6F6D5' : '#EDF2F7'}; border-radius: 4px; border: 1px solid ${det.webfilter_profile ? '#38A169' : '#CBD5E0'};">
                            <span style="font-weight: bold; color: ${det.webfilter_profile ? '#22543D' : '#4A5568'};">Web Filter</span>
                            <span style="font-size: 0.8rem; font-style: italic;">${det.webfilter_profile || 'Désactivé'}</span>
                        </div>
                        <div style="display: flex; justify-content: space-between; align-items: center; padding: 6px 10px; background: ${det.ssl_inspection ? '#EBF8FF' : '#EDF2F7'}; border-radius: 4px; border: 1px solid ${det.ssl_inspection ? '#3182CE' : '#CBD5E0'};">
                            <span style="font-weight: bold; color: ${det.ssl_inspection ? '#2B6CB0' : '#4A5568'};">SSL Inspection</span>
                            <span style="font-size: 0.8rem; font-style: italic;">${det.ssl_inspection ? 'Activé' : 'Désactivé'}</span>
                        </div>
                    </div>
                `;
            } else {
                Object.entries(data.details).forEach(([key, val]) => {
                    if (val && typeof val !== 'object') {
                        htmlContent += `<p style="margin: 3px 0;"><strong>${key} :</strong> ${val}</p>`;
                    } else if (Array.isArray(val)) {
                        htmlContent += `<p style="margin: 3px 0;"><strong>${key} :</strong> ${val.join(', ')}</p>`;
                    }
                });
            }
        }

        // Source Traceability Trigger
        if (data.details && (data.details.source_file || data.details.vdom)) {
            // Find in analysis model to get actual raw source lines
            const matchedSource = this.findSourceLocation(data);
            if (matchedSource) {
                htmlContent += `
                    <button class="source-btn" onclick="app.showSourceBlock('${matchedSource.filename}', ${matchedSource.start_line}, ${matchedSource.end_line})">
                        Voir la configuration source (${matchedSource.filename})
                    </button>
                `;
            }
        }

        panel.innerHTML = htmlContent;
    }

    findSourceLocation(data) {
        // Traverses latest analysis device to find start and end lines of interface, policy, etc
        const dev = this.analysisData.device;
        const name = data.details ? (data.details.name || data.details.policy_id) : null;
        if (!name) return null;

        for (const [v_name, vdom] of Object.entries(dev.vdoms)) {
            // Check interface
            if (vdom.interfaces[name]) {
                const item = vdom.interfaces[name];
                return { filename: item.source_file, start_line: item.start_line, end_line: item.start_line + 15 };
            }
            // Check policy
            const matchedPolicy = vdom.policies.find(p => String(p.policy_id) === String(name));
            if (matchedPolicy) {
                return { filename: matchedPolicy.source_file, start_line: matchedPolicy.start_line, end_line: matchedPolicy.start_line + 20 };
            }
            // Check VIP
            if (vdom.vips[name]) {
                const item = vdom.vips[name];
                return { filename: item.source_file, start_line: item.start_line, end_line: item.start_line + 8 };
            }
            // Check VPN
            if (vdom.vpns[name]) {
                const item = vdom.vpns[name];
                return { filename: item.source_file, start_line: item.start_line, end_line: item.start_line + 10 };
            }
        }
        return null;
    }

    async showSourceBlock(filename, start, end) {
        try {
            const res = await fetch('/api/source-code', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ filename, start_line: start, end_line: end })
            });
            const data = await res.json();

            // Show inside modal
            document.getElementById('source-modal-file').textContent = data.filename;
            document.getElementById('source-modal-lines').textContent = `${data.start} - ${data.end}`;
            document.getElementById('source-modal-code').textContent = data.code || 'Pas de source trouvée.';

            // Populate mini tracing panel at the bottom right sidebar too
            document.getElementById('source-tracing-panel').textContent = data.code;

            document.getElementById('source-modal').style.display = 'block';
        } catch (error) {
            console.error(error);
            alert("Impossible de charger le code source.");
        }
    }

    onCloseSourceModal() {
        document.getElementById('source-modal').style.display = 'none';
    }

    performGlobalSearch() {
        const query = document.getElementById('global-search').value.toLowerCase().trim();
        if (!query || !this.cy) return;

        // Find match in nodes or edges
        let matchedNode = null;
        this.cy.nodes().forEach(node => {
            const label = (node.data('label') || '').toLowerCase();
            const type = (node.data('type') || '').toLowerCase();
            const detailsStr = JSON.stringify(node.data('details') || '').toLowerCase();

            if (label.includes(query) || type.includes(query) || detailsStr.includes(query)) {
                node.style('border-color', '#C1272D');
                node.style('border-width', '4px');
                if (!matchedNode) matchedNode = node;
            } else {
                // Reset styles
                node.style('border-width', '2px');
            }
        });

        if (matchedNode) {
            // Autocenter cytoscape on match
            this.cy.animate({
                center: { eles: matchedNode },
                zoom: 1.2
            }, { duration: 400 });
        } else {
            alert("Aucun élément correspondant trouvé.");
        }
    }

    switchInventory(invType, tabElement = null) {
        this.currentInventory = invType;
        if (tabElement) {
            document.querySelectorAll('.inv-tab').forEach(t => t.classList.remove('active'));
            tabElement.classList.add('active');
        }

        const container = document.getElementById('inventory-table-container');
        if (!this.analysisData) return;

        const dev = this.analysisData.device;
        let htmlTable = '<table><thead>';

        if (invType === 'interfaces') {
            htmlTable += '<tr><th>VDOM</th><th>Nom</th><th>Alias</th><th>Type</th><th>IP</th><th>Masque</th><th>Rôle</th><th>VLAN ID</th><th>Statut</th></tr></thead><tbody>';
            Object.entries(dev.vdoms).forEach(([v_name, vdom]) => {
                Object.values(vdom.interfaces).forEach(i => {
                    htmlTable += `
                        <tr ondblclick="app.centerOnGraph('intf_${v_name}_${i.name}')">
                            <td>${v_name}</td>
                            <td><strong>${i.name}</strong></td>
                            <td>${i.alias || '-'}</td>
                            <td>${i.type}</td>
                            <td>${i.ip}</td>
                            <td>${i.mask}</td>
                            <td>${i.role}</td>
                            <td>${i.vlan_id || '-'}</td>
                            <td><span style="color:${i.status==='up'?'green':'red'}">${i.status}</span></td>
                        </tr>
                    `;
                });
            });

        } else if (invType === 'zones') {
            htmlTable += '<tr><th>VDOM</th><th>Zone</th><th>Interfaces Membres</th><th>Intrazone</th><th>Rôle Supposé</th></tr></thead><tbody>';
            Object.entries(dev.vdoms).forEach(([v_name, vdom]) => {
                Object.values(vdom.zones).forEach(z => {
                    htmlTable += `
                        <tr ondblclick="app.centerOnGraph('zone_${v_name}_${z.name}')">
                            <td>${v_name}</td>
                            <td><strong>${z.name}</strong></td>
                            <td>${z.interfaces.join(', ')}</td>
                            <td>${z.intrazone}</td>
                            <td>${z.role}</td>
                        </tr>
                    `;
                });
            });

        } else if (invType === 'routes') {
            htmlTable += '<tr><th>VDOM</th><th>Destination</th><th>Passerelle</th><th>Interface</th><th>Distance</th><th>Priorité</th><th>Type</th></tr></thead><tbody>';
            Object.entries(dev.vdoms).forEach(([v_name, vdom]) => {
                vdom.routes.forEach(r => {
                    htmlTable += `
                        <tr>
                            <td>${v_name}</td>
                            <td><strong>${r.destination}</strong></td>
                            <td>${r.gateway}</td>
                            <td>${r.device}</td>
                            <td>${r.distance}</td>
                            <td>${r.priority}</td>
                            <td>${r.type}</td>
                        </tr>
                    `;
                });
            });

        } else if (invType === 'objects') {
            htmlTable += '<tr><th>VDOM</th><th>Nom</th><th>Type</th><th>Valeur</th><th>Interface Associée</th></tr></thead><tbody>';
            Object.entries(dev.vdoms).forEach(([v_name, vdom]) => {
                Object.values(vdom.address_objects).forEach(obj => {
                    htmlTable += `
                        <tr ondblclick="app.centerOnGraph('subnet_${v_name}_${obj.name}')">
                            <td>${v_name}</td>
                            <td><strong>${obj.name}</strong></td>
                            <td>${obj.type}</td>
                            <td>${obj.value}</td>
                            <td>${obj.associated_interface || '-'}</td>
                        </tr>
                    `;
                });
            });

        } else if (invType === 'policies') {
            htmlTable += '<tr><th>VDOM</th><th>ID Règle</th><th>Nom</th><th>Source</th><th>Destination</th><th>Sources Addr</th><th>Dests Addr</th><th>Services</th><th>Action</th><th>NAT</th></tr></thead><tbody>';
            Object.entries(dev.vdoms).forEach(([v_name, vdom]) => {
                vdom.policies.forEach(p => {
                    htmlTable += `
                        <tr>
                            <td>${v_name}</td>
                            <td>${p.policy_id}</td>
                            <td><strong>${p.name || '-'}</strong></td>
                            <td>${p.srcintf.join(', ')}</td>
                            <td>${p.dstintf.join(', ')}</td>
                            <td>${p.srcaddr.join(', ')}</td>
                            <td>${p.dstaddr.join(', ')}</td>
                            <td>${p.service.join(', ')}</td>
                            <td><span style="color:${p.action==='accept'?'green':'red'}">${p.action}</span></td>
                            <td>${p.nat ? 'Oui':'Non'}</td>
                        </tr>
                    `;
                });
            });

        } else if (invType === 'vips') {
            htmlTable += '<tr><th>VDOM</th><th>Nom VIP</th><th>IP Externe</th><th>IP Interne</th><th>Intf Ext</th><th>Port Forwarding</th></tr></thead><tbody>';
            Object.entries(dev.vdoms).forEach(([v_name, vdom]) => {
                Object.values(vdom.vips).forEach(v => {
                    htmlTable += `
                        <tr ondblclick="app.centerOnGraph('vip_${v_name}_${v.name}')">
                            <td>${v_name}</td>
                            <td><strong>${v.name}</strong></td>
                            <td>${v.extip}</td>
                            <td>${v.mappedip}</td>
                            <td>${v.extintf}</td>
                            <td>${v.portforward ? 'Oui':'Non'}</td>
                        </tr>
                    `;
                });
            });

        } else if (invType === 'vpns') {
            htmlTable += '<tr><th>VDOM</th><th>Nom VPN</th><th>Type</th><th>GW Distante</th><th>Interface</th><th>Local Network</th><th>Remote Network</th></tr></thead><tbody>';
            Object.entries(dev.vdoms).forEach(([v_name, vdom]) => {
                Object.values(vdom.vpns).forEach(vpn => {
                    htmlTable += `
                        <tr ondblclick="app.centerOnGraph('vpn_${v_name}_${vpn.name}')">
                            <td>${v_name}</td>
                            <td><strong>${vpn.name}</strong></td>
                            <td>${vpn.type}</td>
                            <td>${vpn.remote_gw || '-'}</td>
                            <td>${vpn.interface || '-'}</td>
                            <td>${vpn.local_subnet || '-'}</td>
                            <td>${vpn.remote_subnet || '-'}</td>
                        </tr>
                    `;
                });
            });

        } else if (invType === 'findings') {
            htmlTable += '<tr><th>VDOM</th><th>Sévérité</th><th>Catégorie</th><th>Description de l\'Anomalie</th><th>Régler</th></tr></thead><tbody>';
            dev.findings.forEach(f => {
                let sevClass = `severity-${f.severity}`;
                htmlTable += `
                    <tr class="${sevClass}">
                        <td>${f.vdom}</td>
                        <td><strong>${f.severity.toUpperCase()}</strong></td>
                        <td>${f.category}</td>
                        <td>${f.description}</td>
                        <td><button onclick="app.showFindingFix('${f.id}')" style="padding: 2px 5px; font-size: 0.75rem;">Voir</button></td>
                    </tr>
                `;
            });
        }

        htmlTable += '</tbody></table>';
        container.innerHTML = htmlTable;
    }

    centerOnGraph(nodeId) {
        if (!this.cy) return;
        const safeId = nodeId.replace(/ /g, '_');
        const node = this.cy.getElementById(safeId);
        if (node && node.length > 0) {
            this.cy.animate({
                center: { eles: node },
                zoom: 1.5
            }, { duration: 500 });
            this.showProperties(node);
        } else {
            alert("L'élément correspondant n'est pas affiché avec les filtres actuels.");
        }
    }

    showFindingFix(findingId) {
        const finding = this.analysisData.device.findings.find(f => f.id === findingId);
        if (!finding) return;

        alert(`Contrôle de Cohérence [${finding.severity.toUpperCase()}] : \n\n${finding.description}\n\nCatégorie : ${finding.category}\nCible : ${finding.item_type} -> ${finding.item_name}`);
    }

    async exportDrawio() {
        if (!this.analysisData) return;

        // Grab current coordinates of elements in Cytoscape so they are perfectly preserved in Draw.io
        const coordinates = {};
        this.cy.nodes().forEach(node => {
            const pos = node.position();
            coordinates[node.id()] = {
                x: pos.x,
                y: pos.y,
                width: node.width(),
                height: node.height()
            };
        });

        try {
            const res = await fetch('/api/export/drawio', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ coordinates })
            });
            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `architecture_${this.analysisData.device.hostname}.drawio`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        } catch (error) {
            console.error(error);
            alert("Erreur lors de l'export Draw.io.");
        }
    }

    downloadCurrentCSV() {
        if (!this.analysisData) return;
        window.open(`/api/export/csv?type=${this.currentInventory}`, '_blank');
    }

    exportJSON() {
        if (!this.analysisData) return;
        window.open('/api/export/json', '_blank');
    }

    exportStandaloneHTML() {
        // Generates an interactive 100% offline HTML file containing the model topology
        // It embeds cytoscape from a CDN fallback but bundles the parsed JSON inside, so it can run autonomously
        const fullJSON = JSON.stringify({
            device: this.analysisData.device,
            topology: this.analysisData.topology
        });

        const template = `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Architecture FortiGate Autonome — ${this.analysisData.device.hostname}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.26.0/cytoscape.min.js"></script>
    <style>
        body { margin:0; padding:0; font-family:sans-serif; height:100vh; display:flex; flex-direction:column; }
        header { background:#1A202C; color:white; padding:15px; border-bottom:3px solid #C1272D; }
        #cy { flex:1; background:#FAFAFA; }
    </style>
</head>
<body>
    <header>
        <h1 style="margin:0; font-size:1.4rem;">Topologie Interactive - ${this.analysisData.device.hostname}</h1>
        <p style="margin:5px 0 0; font-size:0.85rem; color:#A0AEC0;">Généré automatiquement par FortiGate Network Mapper. Glissez-déposez pour réorganiser.</p>
    </header>
    <div id="cy"></div>
    <script>
        const data = ${fullJSON};
        const cyElements = [];
        data.topology.nodes.forEach(n => {
            cyElements.push({ data: { id: n.id, label: n.label, type: n.type, parent: n.parent } });
        });
        data.topology.edges.forEach(e => {
            cyElements.push({ data: { id: e.id, source: e.source, target: e.target, label: e.label } });
        });
        cytoscape({
            container: document.getElementById('cy'),
            elements: cyElements,
            style: [
                { selector: 'node', style: { 'background-color':'#FFF', 'border-color':'#2D3748', 'border-width':'2px', 'label':'data(label)', 'text-valign':'center', 'text-halign':'center', 'font-size':'10px', 'shape':'round-rectangle', 'width':'110px', 'height':'55px' } },
                { selector: 'node[type="vdom"]', style: { 'background-color':'rgba(235, 248, 255, 0.4)', 'border-color':'#3182CE', 'text-valign':'top' } },
                { selector: 'node[type="zone"]', style: { 'background-color':'rgba(254, 252, 191, 0.2)', 'border-color':'#ECC94B', 'border-style':'dashed', 'text-valign':'top' } },
                { selector: 'edge', style: { 'width':2, 'line-color':'#4A5568', 'target-arrow-shape':'triangle', 'curve-style':'bezier', 'label':'data(label)', 'font-size':'8px' } }
            ],
            layout: { name: 'cose', padding: 40 }
        });
    </script>
</body>
</html>`;

        const blob = new Blob([template], { type: 'text/html' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `architecture_interactive_${this.analysisData.device.hostname}.html`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    }

    async resetAll() {
        if (confirm("Voulez-vous vraiment réinitialiser toutes les configurations et données en cours ?")) {
            await fetch('/api/reset', { method: 'POST' });
            this.selectedFiles = {
                'global': null,
                'b-global': null,
                'vdom-1': null,
                'vdom-2': null,
                'vdom-3': null
            };
            this.analysisData = null;
            this.cy = null;

            // Clear dropzones UI
            document.querySelectorAll('.file-list').forEach(el => el.style.display = 'none');
            document.getElementById('chk-anonymize').checked = false;

            this.showImportScreen();
        }
    }
}

// Instantiate global application
const app = new FortiGateApp();
