// ONTOLOGY REASONER MOCK INFERRED DATASETS
const ontologyData = {
    actors: [
        { id: "APT29", name: "APT29 (Cozy Bear)", motivation: "Espionaje Estatal", isHighRisk: true, techniques: ["T1071 (Application Layer Protocol)", "T1547 (Boot or Logon Autostart)"] },
        { id: "APT28", name: "APT28 (Fancy Bear)", motivation: "Sabotaje y Espionaje", isHighRisk: true, techniques: ["T1059 (Command and Scripting Interpreter)", "T1566 (Phishing)"] },
        { id: "WizardSpider", name: "Wizard Spider", motivation: "Económico (Extorsión)", isHighRisk: true, techniques: ["T1486 (Data Encrypted for Impact)", "T1055 (Process Injection)"] },
        { id: "LazarusGroup", name: "Lazarus Group", motivation: "Financiero / Estatal", isHighRisk: true, techniques: ["T1566 (Phishing)", "T1071 (Application Layer Protocol)"] },
        { id: "TA505", name: "TA505", motivation: "Económico (Crimen)", isHighRisk: false, techniques: ["T1204 (User Execution)"] }
    ],
    malware: [
        { name: "Cobalt Strike", type: "Trojan_Horse", techniques: "T1071, T1055", cves: "CVE-2023-38831, CVE-2022-30190", trace: "Cobalt_Strike ➔ malware_is_deployed_by_actor ➔ APT29 ➔ actor_uses_technique ➔ T1071 ➔ technique_implemented_by_pattern ➔ CAPEC-148 ➔ attack_pattern_targets_weakness ➔ CWE-20 ➔ weakness_classifies_vulnerability ➔ CVE-2023-38831" },
        { name: "Ryuk", type: "Ransomware", techniques: "T1486", cves: "CVE-2021-34527", trace: "Ryuk ➔ malware_is_deployed_by_actor ➔ WizardSpider ➔ actor_uses_technique ➔ T1486 ➔ technique_implemented_by_pattern ➔ CAPEC-586 ➔ attack_pattern_targets_weakness ➔ CWE-121 ➔ weakness_classifies_vulnerability ➔ CVE-2021-34527" },
        { name: "Pegasus", type: "Spyware", techniques: "T1059", cves: "CVE-2021-30860, CVE-2023-41064", trace: "Pegasus ➔ malware_uses_technique ➔ T1059 ➔ technique_implemented_by_pattern ➔ CAPEC-242 ➔ attack_pattern_targets_weakness ➔ CWE-119 ➔ weakness_classifies_vulnerability ➔ CVE-2021-30860" },
        { name: "Conti", type: "Ransomware", techniques: "T1486, T1055", cves: "CVE-2020-0601", trace: "Conti ➔ malware_uses_technique ➔ T1486 ➔ technique_implemented_by_pattern ➔ CAPEC-586 ➔ attack_pattern_targets_weakness ➔ CWE-295 ➔ weakness_classifies_vulnerability ➔ CVE-2020-0601" }
    ],
    software: [
        { name: "PsExec.exe", actor: "APT29, TA505", techniques: "T1059 (Ejecución de Comandos)", cves: "CVE-2021-31860", trace: "PsExec.exe ➔ software_is_used_by_actor ➔ APT29 ➔ actor_uses_technique ➔ T1059 ➔ technique_implemented_by_pattern ➔ CAPEC-242 ➔ attack_pattern_targets_weakness ➔ CWE-119 ➔ weakness_classifies_vulnerability ➔ CVE-2021-31860" },
        { name: "Mimikatz", actor: "APT28, WizardSpider", techniques: "T1003 (Acceso a Credenciales)", cves: "CVE-2022-26925", trace: "Mimikatz ➔ software_is_used_by_actor ➔ APT28 ➔ actor_uses_technique ➔ T1003 ➔ technique_implemented_by_pattern ➔ CAPEC-551 ➔ attack_pattern_targets_weakness ➔ CWE-287 ➔ weakness_classifies_vulnerability ➔ CVE-2022-26925" },
        { name: "7-Zip Utility", actor: "Lazarus Group", techniques: "T1560 (Archivo de Datos)", cves: "CVE-2022-29072", trace: "7-Zip Utility ➔ software_uses_technique ➔ T1560 ➔ technique_implemented_by_pattern ➔ CAPEC-97 ➔ attack_pattern_targets_weakness ➔ CWE-94 ➔ weakness_classifies_vulnerability ➔ CVE-2022-29072" },
        { name: "AnyDesk.exe", actor: "Wizard Spider", techniques: "T1219 (Software de Acceso Remoto)", cves: "CVE-2023-32439", trace: "AnyDesk.exe ➔ software_is_used_by_actor ➔ WizardSpider ➔ actor_uses_technique ➔ T1219 ➔ technique_implemented_by_pattern ➔ CAPEC-563 ➔ attack_pattern_targets_weakness ➔ CWE-843 ➔ weakness_classifies_vulnerability ➔ CVE-2023-32439" }
    ],
    vulnerabilities: [
        { cve: "CVE-2023-38831", desc: "Vulnerabilidad en WinRAR que permite la ejecución de código remoto mediante archivos modificados.", severity: 9.8, type: "Critical_Vulnerability", cwe: "CWE-20 (Improper Input Validation)", mitigated: true },
        { cve: "CVE-2022-30190", desc: "Falla Follina en la Herramienta de Diagnóstico de Soporte de Microsoft Windows (MSDT) que otorga ejecución remota.", severity: 7.8, type: "High_Risk_Vulnerability", cwe: "CWE-94 (Code Injection)", mitigated: false },
        { cve: "CVE-2021-34527", desc: "Falla PrintNightmare en la cola de impresión de Windows que facilita privilegios elevados de SYSTEM.", severity: 8.8, type: "High_Risk_Vulnerability", cwe: "CWE-121 (Stack-based Buffer Overflow)", mitigated: true },
        { cve: "CVE-2021-30860", desc: "Falla ForcedEntry de Apple iOS que permite ejecución remota sin interacción a través de iMessage.", severity: 9.8, type: "Critical_Vulnerability", cwe: "CWE-119 (Memory Buffer Errors)", mitigated: true },
        { cve: "CVE-2023-41064", desc: "Falla en el procesamiento de imágenes que permite ejecución de código malicioso al abrir adjuntos.", severity: 8.6, type: "High_Risk_Vulnerability", cwe: "CWE-119 (Memory Buffer Errors)", mitigated: false },
        { cve: "CVE-2020-0601", desc: "Falla en la validación de certificados CryptoAPI de Windows que compromete conexiones SSL/TLS.", severity: 5.4, type: "Medium_Risk_Vulnerability", cwe: "CWE-295 (Improper Certificate Validation)", mitigated: true },
        { cve: "CVE-2022-26925", desc: "Vulnerabilidad de spoofing en Windows LSA que facilita ataques de retransmisión NTM y toma de dominios AD.", severity: 8.1, type: "High_Risk_Vulnerability", cwe: "CWE-287 (Improper Authentication)", mitigated: true },
        { cve: "CVE-2022-29072", desc: "Falla en 7-Zip en sistemas Windows que permite escalado de privilegios mediante ejecución de código local.", severity: 7.5, type: "High_Risk_Vulnerability", cwe: "CWE-94 (Code Injection)", mitigated: false },
        { cve: "CVE-2023-32439", desc: "Falla de día cero en el Kernel de Apple de tipo confusión de tipo (Type Confusion) explotada de forma activa.", severity: 9.8, type: "Critical_Vulnerability", cwe: "CWE-843 (Access of Resource Using Incompatible Type)", mitigated: true }
    ]
};

// INITIALIZATION & TAB NAVIGATION LOGIC
document.addEventListener("DOMContentLoaded", () => {
    initDashboardMetrics();
    renderAllTables();
    setupNavigation();
    setupFilters();
    setupModalClose();
});

function setupNavigation() {
    const navButtons = document.querySelectorAll(".nav-btn");
    const tabContents = document.querySelectorAll(".tab-content");

    navButtons.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-target");

            navButtons.forEach(b => b.classList.remove("active"));
            tabContents.forEach(tc => tc.classList.remove("active"));

            btn.classList.add("active");
            document.getElementById(targetId).classList.add("active");
        });
    });
}

// COMPUTE RESUMES FROM GRAFO INFERRED DATA
function initDashboardMetrics() {
    const highRiskActors = ontologyData.actors.filter(a => a.isHighRisk).length;
    const criticalCves = ontologyData.vulnerabilities.filter(v => v.severity > 9.0).length;
    
    // Inferred triples is calculated based on simulated Pellet execution mapping results
    const inferredCount = (ontologyData.malware.length * 2) + (ontologyData.software.length * 3) + ontologyData.vulnerabilities.filter(v => v.mitigated).length;

    document.getElementById("count-high-actors").innerText = highRiskActors;
    document.getElementById("count-critical-cve").innerText = criticalCves;
    document.getElementById("count-inferred-triples").innerText = `+${inferredCount * 14}`;
}

// RENDER RAG DATA TO TABLES
function renderAllTables() {
    renderActorsTable(ontologyData.actors);
    renderMalwareTable(ontologyData.malware);
    renderSoftwareTable(ontologyData.software);
    renderVulnerabilitiesTable(ontologyData.vulnerabilities);
}

function renderActorsTable(data) {
    const tbody = document.querySelector("#table-actors tbody");
    tbody.innerHTML = "";
    data.forEach(actor => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><strong>${actor.name}</strong></td>
            <td>${actor.motivation}</td>
            <td>${actor.isHighRisk ? '<span class="badge badge-red">High_Risk_Threat_Actor</span>' : '<span class="badge badge-metal">Threat_Actor (Base)</span>'}</td>
            <td><button class="action-btn" onclick="openTraceModal('Actor: ${actor.name}', 'Regla SWRL: Threat_Actor(?a) ^ actor_uses_technique(?a, ?t) ^ High_Impact_Technique(?t) -> High_Risk_Threat_Actor(?a)\n\nEl actor utiliza técnicas directamente asociadas a vulnerabilidades con CVSS superior a 9.0.')">Ver Regla</button></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderMalwareTable(data) {
    const tbody = document.querySelector("#table-malware tbody");
    tbody.innerHTML = "";
    data.forEach(m => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><span class="text-red">☣️ ${m.name}</span></td>
            <td><span class="badge badge-amber">${m.type}</span></td>
            <td><span class="text-yellow">${m.techniques}</span> (Inferido)</td>
            <td><span class="text-blue">${m.cves}</span></td>
            <td><button class="action-btn" onclick="openTraceModal('${m.name}', '${m.trace}')">Trazar Grafo</button></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderSoftwareTable(data) {
    const tbody = document.querySelector("#table-software tbody");
    tbody.innerHTML = "";
    data.forEach(s => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><span class="text-blue">🛠️ ${s.name}</span></td>
            <td>${s.actor}</td>
            <td>${s.techniques}</td>
            <td><span class="text-red">${s.cves}</span> (Inferido)</td>
            <td><button class="action-btn" onclick="openTraceModal('${s.name}', '${s.trace}')">Trazar Grafo</button></td>
        `;
        tbody.appendChild(tr);
    });
}

function renderVulnerabilitiesTable(data) {
    const tbody = document.querySelector("#table-vulnerabilities tbody");
    tbody.innerHTML = "";
    data.forEach(v => {
        let badgeClass = "badge-blue";
        if (v.type === "Critical_Vulnerability") badgeClass = "badge-red";
        else if (v.type === "High_Risk_Vulnerability") badgeClass = "badge-amber";

        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><strong>${v.cve}</strong></td>
            <td style="max-width: 300px; font-size:12px; color: #8a99ad;">${v.desc}</td>
            <td><span class="badge ${badgeClass}">${v.severity} (${v.type.split('_')[0]})</span></td>
            <td><span class="text-yellow">${v.cwe}</span></td>
            <td>${v.mitigated ? '<span class="badge badge-green">Mitigated_Vulnerability</span>' : '<span class="badge badge-metal">No Mitigada</span>'}</td>
        `;
        tbody.appendChild(tr);
    });
}

// DYNAMIC SEARCH FILTERS
function setupFilters() {
    document.getElementById("search-actors").addEventListener("input", (e) => {
        const val = e.target.value.toLowerCase();
        const filtered = ontologyData.actors.filter(a => a.name.toLowerCase().includes(val) || a.motivation.toLowerCase().includes(val));
        renderActorsTable(filtered);
    });

    document.getElementById("filter-cve-severity").addEventListener("change", (e) => {
        const val = e.target.value;
        if (val === "ALL") {
            renderVulnerabilitiesTable(ontologyData.vulnerabilities);
        } else {
            const filtered = ontologyData.vulnerabilities.filter(v => v.type === val);
            renderVulnerabilitiesTable(filtered);
        }
    });
}

// MODAL CONTROLLER (FOR EXPLAINING COMPUTE PROPERTY CHAINS)
function openTraceModal(title, traceMessage) {
    document.getElementById("modal-title").innerText = `[AUDITORÍA SEMÁNTICA]: ${title.toUpperCase()}`;
    document.getElementById("modal-trace").innerText = traceMessage;
    
    const modal = document.getElementById("cyber-modal");
    modal.classList.add("active");
}

function setupModalClose() {
    const modal = document.getElementById("cyber-modal");
    document.getElementById("close-modal-btn").addEventListener("click", () => {
        modal.classList.remove("active");
    });
    
    window.addEventListener("click", (e) => {
        if (e.target === modal) {
            modal.classList.remove("active");
        }
    });
}