/**
 * CYBER-ONTOLOGY DASHBOARD v3.0
 * Parser RDF/Turtle + Visualización de TODOS los individuos
 * Carga y procesa: data/tfgontologiaciberseguridad.ttl
 */

let ontologyData = {
    metadata: {
        totalIndividuals: 0,
        totalTriples: 0,
        totalClasses: 0
    },
    actors: [],
    malware: [],
    software: [],
    vulnerabilities: [],
    weaknesses: [],
    techniques: [],
    allTriples: [] // Almacenar todos los triples para análisis
};

/**
 * FASE 1: Cargar y parsear Turtle
 */
async function loadTurtleOntology() {
    try {
        console.log('📖 Cargando ontología Turtle...');
        const response = await fetch('data/tfgontologiaciberseguridad.ttl');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const turtleData = await response.text();
        console.log(`✓ Archivo cargado: ${(turtleData.length / 1024).toFixed(2)} KB`);
        
        // Parsear Turtle
        const triples = parseTurtle(turtleData);
        console.log(`✓ Parseados ${triples.length} triples`);
        
        // Procesar triples
        processTriples(triples);
        
        console.log('✓ Ontología procesada correctamente');
        return true;
    } catch (error) {
        console.error('✗ Error cargando ontología:', error);
        return false;
    }
}

/**
 * Parser RDF Turtle simple (sin librería externa)
 */
function parseTurtle(turtleText) {
    const triples = [];
    const lines = turtleText.split('\n');
    
    let currentSubject = null;
    let prefixes = {};
    
    for (let line of lines) {
        // Ignorar comentarios y líneas vacías
        line = line.trim();
        if (!line || line.startsWith('#')) continue;
        
        // Procesar prefijos
        if (line.startsWith('@prefix')) {
            const match = line.match(/@prefix\s+(\w+):\s+<([^>]+)>/);
            if (match) {
                prefixes[match[1]] = match[2];
                console.log(`  Prefix ${match[1]}: ${match[2]}`);
            }
            continue;
        }
        
        // Procesar triples
        if (line.includes(' ') && !line.startsWith('@')) {
            // Dividir por espacios (simple)
            const parts = line.split(/\s+/);
            
            if (parts.length >= 3) {
                let subject = expandURI(parts[0], prefixes);
                let predicate = expandURI(parts[1], prefixes);
                
                // Obtener objeto (puede ser URI, literal o blank node)
                let object = '';
                let i = 2;
                
                if (parts[i].startsWith('"')) {
                    // Literal con comillas
                    let literal = '';
                    while (i < parts.length) {
                        literal += parts[i] + ' ';
                        if (parts[i].endsWith('"')) break;
                        i++;
                    }
                    object = literal.trim().slice(1, -1); // Remover comillas
                } else {
                    object = expandURI(parts[i], prefixes);
                }
                
                if (subject && predicate) {
                    triples.push({
                        subject: subject,
                        predicate: predicate,
                        object: object
                    });
                    
                    currentSubject = subject;
                }
            }
        }
    }
    
    return triples;
}

/**
 * Expandir URI prefijadas
 */
function expandURI(uri, prefixes) {
    if (uri.startsWith('<') && uri.endsWith('>')) {
        return uri.slice(1, -1);
    }
    
    if (uri.includes(':')) {
        const [prefix, local] = uri.split(':');
        if (prefixes[prefix]) {
            return prefixes[prefix] + local;
        }
    }
    
    return uri;
}

/**
 * Procesar todos los triples extraídos
 */
function processTriples(triples) {
    ontologyData.allTriples = triples;
    
    // Namespaces de la ontología
    const ontNS = 'http://ciberseguridad.example.org/ontology#';
    const rdfNS = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#';
    const rdfsNS = 'http://www.w3.org/2000/01/rdf-schema#';
    
    // Crear mapa de individuos por tipo
    const individuosPorTipo = {};
    
    // Primer paso: encontrar todos los individuos (instancias)
    for (let triple of triples) {
        if (triple.predicate === `${rdfNS}type`) {
            const individuo = triple.subject;
            const tipo = triple.object.replace(ontNS, '').replace(rdfNS, '');
            
            if (!individuosPorTipo[tipo]) {
                individuosPorTipo[tipo] = [];
            }
            
            if (!individuosPorTipo[tipo].includes(individuo)) {
                individuosPorTipo[tipo].push(individuo);
            }
        }
    }
    
    console.log('📊 Individuos por tipo:');
    for (let tipo in individuosPorTipo) {
        console.log(`  ${tipo}: ${individuosPorTipo[tipo].length}`);
    }
    
    // Segundo paso: Extraer propiedades de cada individuo
    ontologyData.actors = extractIndividuals(triples, individuosPorTipo, ['ThreatActor', 'HighRiskThreatActor'], ontNS, rdfsNS);
    ontologyData.vulnerabilities = extractIndividuals(triples, individuosPorTipo, ['Vulnerability', 'CriticalVulnerability', 'HighRiskVulnerability', 'MediumRiskVulnerability', 'MitigatedVulnerability'], ontNS, rdfsNS);
    ontologyData.malware = extractIndividuals(triples, individuosPorTipo, ['Malware', 'Ransomware', 'TrojanHorse', 'Spyware'], ontNS, rdfsNS);
    ontologyData.software = extractIndividuals(triples, individuosPorTipo, ['Software'], ontNS, rdfsNS);
    ontologyData.weaknesses = extractIndividuals(triples, individuosPorTipo, ['Weakness', 'CWECategory'], ontNS, rdfsNS);
    ontologyData.techniques = extractIndividuals(triples, individuosPorTipo, ['AttackTechnique', 'HighImpactTechnique'], ontNS, rdfsNS);
    
    // Actualizar metadata
    let totalIndividuos = 0;
    for (let tipo in individuosPorTipo) {
        totalIndividuos += individuosPorTipo[tipo].length;
    }
    
    ontologyData.metadata = {
        totalIndividuals: totalIndividuos,
        totalTriples: triples.length,
        totalClasses: Object.keys(individuosPorTipo).length,
        clasesEncontradas: Object.keys(individuosPorTipo)
    };
}

/**
 * Extraer todos los individuos de tipos específicos
 */
function extractIndividuals(triples, individuosPorTipo, tipos, ontNS, rdfsNS) {
    const rdfNS = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#';
    const individuos = [];
    
    // Recolectar todos los individuos de los tipos especificados
    let todosLosIndividuos = [];
    for (let tipo of tipos) {
        if (individuosPorTipo[tipo]) {
            todosLosIndividuos = todosLosIndividuos.concat(individuosPorTipo[tipo]);
        }
    }
    
    // Remover duplicados
    todosLosIndividuos = [...new Set(todosLosIndividuos)];
    
    // Extraer propiedades de cada individuo
    for (let individuo of todosLosIndividuos) {
        const props = {};
        props.uri = individuo;
        props.id = individuo.split('#').pop() || individuo.split('/').pop();
        
        // Extraer todas las propiedades
        for (let triple of triples) {
            if (triple.subject === individuo) {
                const predicado = triple.predicate.replace(ontNS, '').replace(rdfsNS, '').replace(rdfNS, '');
                
                // Agrupar propiedades múltiples
                if (!props[predicado]) {
                    props[predicado] = [];
                }
                props[predicado].push(triple.object);
            }
        }
        
        // Formatear para mejor visualización
        props.label = props.label ? props.label[0] : props.id;
        props.tiposInferidos = [];
        
        for (let triple of triples) {
            if (triple.subject === individuo && triple.predicate === `${rdfNS}type`) {
                props.tiposInferidos.push(triple.object.replace(ontNS, ''));
            }
        }
        
        individuos.push(props);
    }
    
    return individuos;
}

/**
 * FASE 2: Inicialización del Dashboard
 */
document.addEventListener('DOMContentLoaded', async () => {
    console.log('🔧 Inicializando dashboard...');
    
    // Cargar ontología
    const loaded = await loadTurtleOntology();
    
    if (!loaded) {
        console.warn('⚠️ No se pudo cargar Turtle, usando datos fallback');
        // Usar datos fallback si falla
    }
    
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
    const highRiskActors = ontologyData.actors.filter(a => 
        a.tiposInferidos && a.tiposInferidos.includes('HighRiskThreatActor')
    ).length;
    
    const criticalCves = ontologyData.vulnerabilities.filter(v => 
        v.tiposInferidos && v.tiposInferidos.includes('CriticalVulnerability')
    ).length;
    
    const totalInferred = ontologyData.metadata.totalTriples;
    
    document.getElementById('count-high-actors').textContent = highRiskActors;
    document.getElementById('count-critical-cve').textContent = criticalCves;
    document.getElementById('count-inferred-triples').textContent = totalInferred;
    
    console.log(`📊 Métricas actualizadas: ${highRiskActors} actores alto riesgo, ${criticalCves} CVEs críticas`);
}

/**
 * Renderizar todas las tablas
 */
function renderAllTables() {
    console.log(`📋 Renderizando ${ontologyData.actors.length} actores...`);
    console.log(`📋 Renderizando ${ontologyData.vulnerabilities.length} vulnerabilidades...`);
    console.log(`📋 Renderizando ${ontologyData.malware.length} malware...`);
    console.log(`📋 Renderizando ${ontologyData.software.length} software...`);
    
    renderActorsTable(ontologyData.actors);
    renderMalwareTable(ontologyData.malware);
    renderSoftwareTable(ontologyData.software);
    renderVulnerabilitiesTable(ontologyData.vulnerabilities);
}

/**
 * Tabla: THREAT ACTORS (TODOS)
 */
function renderActorsTable(data) {
    const tbody = document.querySelector('#table-actors tbody');
    tbody.innerHTML = '';
    
    if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">No hay actores en la ontología</td></tr>';
        return;
    }
    
    data.forEach((actor, idx) => {
        const isHighRisk = actor.tiposInferidos && actor.tiposInferidos.includes('HighRiskThreatActor');
        const badge = isHighRisk 
            ? '<span class="badge badge-red">HIGH RISK</span>' 
            : '<span class="badge badge-blue">Threat Actor</span>';
        
        const properties = Object.entries(actor)
            .filter(([k, v]) => k !== 'uri' && k !== 'id' && k !== 'label' && k !== 'tiposInferidos' && k !== 'type')
            .map(([k, v]) => `<strong>${k}:</strong> ${Array.isArray(v) ? v.join(', ') : v}`)
            .join('<br>');
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${actor.label}</strong></td>
            <td><small style="color: var(--text-muted);">${actor.id}</small></td>
            <td>${badge}</td>
            <td>
                <button class="action-btn" onclick="openTraceModal('${escapeHtml(actor.label)}', '${escapeHtml(JSON.stringify(actor, null, 2))}')">
                    ℹ️
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

/**
 * Tabla: MALWARE (TODOS)
 */
function renderMalwareTable(data) {
    const tbody = document.querySelector('#table-malware tbody');
    tbody.innerHTML = '';
    
    if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">No hay malware en la ontología</td></tr>';
        return;
    }
    
    data.forEach(m => {
        const tipos = m.tiposInferidos ? m.tiposInferidos.join(', ') : 'Malware';
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="text-red">☣️ ${m.label}</span></td>
            <td><span class="badge badge-amber">${tipos}</span></td>
            <td><small style="color: var(--text-muted);">${m.id}</small></td>
            <td>
                <button class="action-btn" onclick="openTraceModal('${escapeHtml(m.label)}', '${escapeHtml(JSON.stringify(m, null, 2))}')">
                    📋
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

/**
 * Tabla: SOFTWARE (TODOS)
 */
function renderSoftwareTable(data) {
    const tbody = document.querySelector('#table-software tbody');
    tbody.innerHTML = '';
    
    if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center; color: var(--text-muted);">No hay software en la ontología</td></tr>';
        return;
    }
    
    data.forEach(s => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="text-blue">🛠️ ${s.label}</span></td>
            <td><small style="color: var(--text-muted);">${s.id}</small></td>
            <td><span class="text-yellow">${s.tiposInferidos ? s.tiposInferidos.join(', ') : 'Software'}</span></td>
            <td>
                <button class="action-btn" onclick="openTraceModal('${escapeHtml(s.label)}', '${escapeHtml(JSON.stringify(s, null, 2))}')">
                    📋
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

/**
 * Tabla: VULNERABILITIES (TODAS)
 */
function renderVulnerabilitiesTable(data) {
    const tbody = document.querySelector('#table-vulnerabilities tbody');
    tbody.innerHTML = '';
    
    if (data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color: var(--text-muted);">No hay vulnerabilidades en la ontología</td></tr>';
        return;
    }
    
    data.forEach(v => {
        let badgeClass = 'badge-blue';
        let tipo = 'Vulnerability';
        
        if (v.tiposInferidos) {
            if (v.tiposInferidos.includes('CriticalVulnerability')) {
                badgeClass = 'badge-red';
                tipo = 'CRITICAL';
            } else if (v.tiposInferidos.includes('HighRiskVulnerability')) {
                badgeClass = 'badge-amber';
                tipo = 'HIGH RISK';
            } else if (v.tiposInferidos.includes('MediumRiskVulnerability')) {
                badgeClass = 'badge-metal';
                tipo = 'MEDIUM';
            } else if (v.tiposInferidos.includes('MitigatedVulnerability')) {
                badgeClass = 'badge-green';
                tipo = 'MITIGATED';
            }
        }
        
        const severity = v.hasCVSSScore ? v.hasCVSSScore[0] : 'N/A';
        
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${v.label}</strong></td>
            <td><small style="color: var(--text-muted);">${v.id}</small></td>
            <td><span class="badge ${badgeClass}">${tipo}</span></td>
            <td><span class="text-yellow">${severity}</span></td>
            <td>
                <button class="action-btn" onclick="openTraceModal('${escapeHtml(v.label)}', '${escapeHtml(JSON.stringify(v, null, 2))}')">
                    📋
                </button>
            </td>
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
            
            navButtons.forEach(b => b.classList.remove('active'));
            tabContents.forEach(tc => tc.classList.remove('active'));
            
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
    const searchInput = document.getElementById('search-actors');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const val = e.target.value.toLowerCase();
            const filtered = ontologyData.actors.filter(a => 
                a.label.toLowerCase().includes(val) || 
                a.id.toLowerCase().includes(val)
            );
            renderActorsTable(filtered);
        });
    }
    
    const severityFilter = document.getElementById('filter-cve-severity');
    if (severityFilter) {
        severityFilter.addEventListener('change', (e) => {
            const val = e.target.value;
            let filtered = ontologyData.vulnerabilities;
            
            if (val !== 'ALL') {
                filtered = ontologyData.vulnerabilities.filter(v => 
                    v.tiposInferidos && v.tiposInferidos.includes(val)
                );
            }
            
            renderVulnerabilitiesTable(filtered);
        });
    }
}

/**
 * Abrir modal con detalles
 */
function openTraceModal(title, content) {
    const modalTitle = document.getElementById('modal-title');
    const modalTrace = document.getElementById('modal-trace');
    const modal = document.getElementById('cyber-modal');
    
    if (modalTitle && modalTrace && modal) {
        modalTitle.textContent = `[PROPIEDADES]: ${title.toUpperCase()}`;
        modalTrace.textContent = content;
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
