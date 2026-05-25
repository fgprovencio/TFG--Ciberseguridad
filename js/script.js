/**
 * CYBER-ONTOLOGY DASHBOARD
 * Gestor de interfaz para visualizar resultados de inferencias Pellet
 * Carga datos desde data/ontology-data.json
 */

let ontologyData = {
    metadata: {
        totalClasses: 0,
        totalInstances: 0,
        inferredTriples: 0
    },
    actors: [],
    malware: [],
    software: [],
    vulnerabilities: []
};

/**
 * FASE 1: Cargar datos desde JSON
 */
async function loadOntologyData() {
    try {
        const response = await fetch('data/ontology-data.json');
        if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
        ontologyData = await response.json();
        console.log('✓ Ontología cargada exitosamente', ontologyData);
    } catch (error) {
        console.error('✗ Error cargando ontología:', error);
        // Usar datos por defecto si no se puede cargar
        ontologyData = getDefaultData();
    }
}

/**
 * FASE 2: Datos de fallback (si no carga el JSON)
 */
function getDefaultData() {
    return {
        metadata: {
            totalClasses: 943,
            totalInstances: 250,
            inferredTriples: 1847
        },
        actors: [
            {
                id: 'APT1',
                name: 'APT1 (Comment Crew)',
                motivation: 'Espionaje Industrial',
                isHighRisk: true,
                softwares: ['PsExec', 'WMI'],
                techniques: ['T1047', 'T1021', 'T1570'],
                cves: ['CVE-2020-1048', 'CVE-2021-34527']
            },
            {
                id: 'APT28',
                name: 'APT28 (Fancy Bear)',
                motivation: 'Espionaje Estatal',
                isHighRisk: true,
                softwares: ['Mimikatz', 'psexec'],
                techniques: ['T1003', 'T1056', 'T1098'],
                cves: ['CVE-2022-26925', 'CVE-2021-44228']
            },
            {
                id: 'CARBANAK',
                name: 'Carbanak Group',
                motivation: 'Beneficio Económico',
                isHighRisk: true,
                softwares: [],
                techniques: ['T1059', 'T1083', 'T1005'],
                cves: ['CVE-2021-31860']
            }
        ],
        malware: [
            {
                name: 'Cobalt Strike',
                type: 'Trojan Horse',
                techniques: 'T1071, T1055, T1543',
                cves: 'CVE-2023-38831',
                trace: 'Cobalt_Strike ➔ malware_uses_technique ➔ technique_targets_vulnerability ➔ CVE (Inferencia Pellet)'
            },
            {
                name: 'Ryuk',
                type: 'Ransomware',
                techniques: 'T1486, T1570, T1021',
                cves: 'CVE-2021-34527',
                trace: 'Ryuk ➔ malware_deployed_by_actor ➔ actor_uses_technique ➔ CVE (Property Chain)'
            },
            {
                name: 'Emotet',
                type: 'Trojan',
                techniques: 'T1195, T1566, T1059',
                cves: 'CVE-2021-44228',
                trace: 'Emotet ➔ malware_exploits_vulnerability (Cadena de propiedades objeto)'
            }
        ],
        software: [
            {
                name: 'PsExec.exe',
                actor: 'APT1, APT28',
                techniques: 'T1047, T1021',
                cves: 'CVE-2021-31860',
                trace: 'PsExec ➔ software_is_used_by_actor ➔ actor_uses_technique ➔ vulnerability'
            },
            {
                name: 'Mimikatz',
                actor: 'APT28, Carbanak',
                techniques: 'T1003, T1110',
                cves: 'CVE-2022-26925',
                trace: 'Mimikatz ➔ software_compromises_vulnerability (Living off the Land)'
            },
            {
                name: 'WMI (Windows Management Instrumentation)',
                actor: 'APT1',
                techniques: 'T1047, T1059',
                cves: 'CVE-2020-1048',
                trace: 'WMI ➔ software_uses_technique ➔ Attack Pattern ➔ CWE ➔ CVE'
            }
        ],
        vulnerabilities: [
            {
                cve: 'CVE-2021-34527',
                desc: 'Windows Print Spooler Remote Code Execution Vulnerability',
                severity: 9.8,
                type: 'Critical_Vulnerability',
                cwe: 'CWE-78 (OS Command Injection)',
                mitigated: false,
                affectedSoftware: ['Windows 10', 'Windows Server 2019']
            },
            {
                cve: 'CVE-2021-44228',
                desc: 'Apache Log4j Remote Code Execution',
                severity: 10.0,
                type: 'Critical_Vulnerability',
                cwe: 'CWE-94 (Code Injection)',
                mitigated: true,
                affectedSoftware: ['Log4j 2.0-2.14.1']
            },
            {
                cve: 'CVE-2022-26925',
                desc: 'Windows NTLM Relay Attack',
                severity: 8.5,
                type: 'High_Risk_Vulnerability',
                cwe: 'CWE-294 (Authentication Bypass)',
                mitigated: false,
                affectedSoftware: ['Windows 11', 'Windows Server 2022']
            },
            {
                cve: 'CVE-2023-38831',
                desc: 'WinRAR Arbitrary Code Execution',
                severity: 7.8,
                type: 'High_Risk_Vulnerability',
                cwe: 'CWE-434 (Unrestricted Upload)',
                mitigated: false,
                affectedSoftware: ['WinRAR < 6.20']
            },
            {
                cve: 'CVE-2021-31860',
                desc: 'Remote Code Execution via AppX Installer',
                severity: 6.5,
                type: 'Medium_Risk_Vulnerability',
                cwe: 'CWE-426 (Untrusted Search Path)',
                mitigated: false,
                affectedSoftware: ['Windows 10, 11']
            },
            {
                cve: 'CVE-2020-1048',
                desc: 'Windows Privilege Escalation via Print Spooler',
                severity: 5.5,
                type: 'Medium_Risk_Vulnerability',
                cwe: 'CWE-269 (Improper Access Control)',
                mitigated: true,
                affectedSoftware: ['Windows 7 SP1', 'Windows Server 2008']
            }
        ]
    };
}

/**
 * FASE 3: Inicialización del Dashboard
 */
document.addEventListener('DOMContentLoaded', async () => {
    console.log('🔧 Inicializando dashboard...');
    
    // Cargar datos
    await loadOntologyData();
    
    // Renderizar elementos
    initDashboardMetrics();
    renderAllTables();
    setupNavigation();
    setupFilters();
    setupModalClose();
    
    console.log('✓ Dashboard inicializado');
});

/**
 * Calcular y mostrar métricas del dashboard
 */
function initDashboardMetrics() {
    const highRiskActors = ontologyData.actors.filter(a => a.isHighRisk).length;
    const criticalCves = ontologyData.vulnerabilities.filter(v => v.severity >= 9.0).length;
    const totalInferred = (ontologyData.actors.length * 5) + (ontologyData.vulnerabilities.length * 3);
    
    document.getElementById('count-high-actors').textContent = highRiskActors;
    document.getElementById('count-critical-cve').textContent = criticalCves;
    document.getElementById('count-inferred-triples').textContent = `+${totalInferred}`;
}

/**
 * Renderizar todas las tablas
 */
function renderAllTables() {
    renderActorsTable(ontologyData.actors);
    renderMalwareTable(ontologyData.malware);
    renderSoftwareTable(ontologyData.software);
    renderVulnerabilitiesTable(ontologyData.vulnerabilities);
}

/**
 * Tabla: THREAT ACTORS
 */
function renderActorsTable(data) {
    const tbody = document.querySelector('#table-actors tbody');
    tbody.innerHTML = '';
    
    if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">No hay actores de amenaza cargados</td></tr>';
        return;
    }
    
    data.forEach(actor => {
        const softTexto = actor.softwares.length > 0 ? actor.softwares.join(', ') : 'Ninguno detectado';
        const techTexto = actor.techniques.length > 0 ? actor.techniques.join(', ') : 'Ninguna';
        const badge = actor.isHighRisk 
            ? '<span class="badge badge-red">HIGH RISK THREAT ACTOR</span>' 
            : '<span class="badge badge-blue">Threat Actor</span>';
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${actor.name}</strong></td>
            <td><span style="color: var(--neon-amber);">${actor.motivation}</span></td>
            <td>${badge}</td>
            <td>
                <button class="action-btn" onclick="openTraceModal('${actor.name}', 'Actor: ${actor.id}\n\nSoftware utilizado: ${softTexto}\n\nTécnicas (MITRE ATT&amp;CK): ${techTexto}\n\nRegla SWRL (Pellet):\nThreatActor(?a) ^ actorusestechnique(?a, ?t) ^ HighImpactTechnique(?t)\n➔ HighRiskThreatActor(?a)')">
                    ℹ️ Detalles
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

/**
 * Tabla: MALWARE
 */
function renderMalwareTable(data) {
    const tbody = document.querySelector('#table-malware tbody');
    tbody.innerHTML = '';
    
    if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">No hay malware cargado</td></tr>';
        return;
    }
    
    data.forEach(m => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="text-red">☣️ ${m.name}</span></td>
            <td><span class="badge badge-amber">${m.type}</span></td>
            <td><span class="text-yellow">${m.techniques}</span></td>
            <td><span class="text-blue">${m.cves}</span></td>
            <td>
                <button class="action-btn" onclick="openTraceModal('${m.name}', '${escapeHtml(m.trace)}')">
                    🔗 Trazar
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

/**
 * Tabla: SOFTWARE TOOLS
 */
function renderSoftwareTable(data) {
    const tbody = document.querySelector('#table-software tbody');
    tbody.innerHTML = '';
    
    if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">No hay software cargado</td></tr>';
        return;
    }
    
    data.forEach(s => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="text-blue">🛠️ ${s.name}</span></td>
            <td>${s.actor}</td>
            <td><span class="text-yellow">${s.techniques}</span></td>
            <td><span class="text-red">${s.cves}</span></td>
            <td>
                <button class="action-btn" onclick="openTraceModal('${s.name}', '${escapeHtml(s.trace)}')">
                    🔗 Trazar
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

/**
 * Tabla: VULNERABILITIES
 */
function renderVulnerabilitiesTable(data) {
    const tbody = document.querySelector('#table-vulnerabilities tbody');
    tbody.innerHTML = '';
    
    if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No hay vulnerabilidades cargadas</td></tr>';
        return;
    }
    
    data.forEach(v => {
        let badgeClass = 'badge-blue';
        if (v.type === 'Critical_Vulnerability') badgeClass = 'badge-red';
        else if (v.type === 'High_Risk_Vulnerability') badgeClass = 'badge-amber';
        else if (v.type === 'Medium_Risk_Vulnerability') badgeClass = 'badge-metal';
        
        const mitigated = v.mitigated 
            ? '<span class="badge badge-green">✓ MITIGATED</span>' 
            : '<span class="badge badge-red">✗ NO MITIGADA</span>';
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${v.cve}</strong></td>
            <td style="max-width: 300px; font-size: 12px;">${v.desc}</td>
            <td><span class="badge ${badgeClass}">${v.severity} / 10</span></td>
            <td><span class="text-yellow">${v.cwe}</span></td>
            <td>${mitigated}</td>
        `;
        tbody.appendChild(tr);
    });
}

/**
 * Configurar sistema de navegación (pestañas)
 */
function setupNavigation() {
    const navButtons = document.querySelectorAll('.nav-btn');
    const tabContents = document.querySelectorAll('.tab-content');
    
    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetId = btn.getAttribute('data-target');
            
            // Remover clase activa de todos
            navButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(tc => tc.classList.remove('active'));
            
            // Añadir clase activa al actual
            btn.classList.add('active');
            const targetElement = document.getElementById(targetId);
            if (targetElement) {
                targetElement.classList.add('active');
            }
        });
    });
}

/**
 * Configurar filtros y búsqueda
 */
function setupFilters() {
    // Filtro de búsqueda de actores
    const searchInput = document.getElementById('search-actors');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const val = e.target.value.toLowerCase();
            const filtered = ontologyData.actors.filter(a => 
                a.name.toLowerCase().includes(val) || 
                a.motivation.toLowerCase().includes(val)
            );
            renderActorsTable(filtered);
        });
    }
    
    // Filtro de severidad de CVE
    const severityFilter = document.getElementById('filter-cve-severity');
    if (severityFilter) {
        severityFilter.addEventListener('change', (e) => {
            const val = e.target.value;
            if (val === 'ALL') {
                renderVulnerabilitiesTable(ontologyData.vulnerabilities);
            } else {
                const filtered = ontologyData.vulnerabilities.filter(v => v.type === val);
                renderVulnerabilitiesTable(filtered);
            }
        });
    }
}

/**
 * Abrir modal con detalles de inferencia
 */
function openTraceModal(title, traceMessage) {
    const modalTitle = document.getElementById('modal-title');
    const modalTrace = document.getElementById('modal-trace');
    const modal = document.getElementById('cyber-modal');
    
    if (modalTitle && modalTrace && modal) {
        modalTitle.textContent = `[AUDITORÍA SEMÁNTICA]: ${title.toUpperCase()}`;
        modalTrace.textContent = traceMessage;
        modal.classList.add('active');
    }
}

/**
 * Cerrar modal
 */
function setupModalClose() {
    const modal = document.getElementById('cyber-modal');
    const closeBtn = document.getElementById('close-modal-btn');
    
    if (closeBtn) {
        closeBtn.addEventListener('click', () => {
            modal.classList.remove('active');
        });
    }
    
    if (modal) {
        window.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.remove('active');
            }
        });
    }
}

/**
 * Utilidad: Escapar caracteres HTML
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
