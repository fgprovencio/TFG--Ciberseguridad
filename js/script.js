{
    const PREFIXES = `
        PREFIX onto: <http://www.tfguoc.org/ontologia/ciberseguridad/vulnerabilidades/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
    `;

    const DATA_FILES = {
        ontologia: './data/tfg_ontologia_ciberseguridad_vulnerabilidades.rdf',
        nvd1: './data/nvd_data_1.ttl',
        nvd2: './data/nvd_data_2.ttl',
        mitre: './data/mitre_data.ttl',
        mitigaciones: './data/mitigaciones_manual.ttl'
    };

    let store = null;
    let $rdf = null;

    function log(msg, ...rest) {
        console.log(`[script] ${msg}`, ...rest);
    }

    function actualizarStatus(text) {
        const el = document.getElementById("status");
        if (el) el.textContent = text;
        log("STATUS:", text);
    }

    function ensureRdflib() {
        if ($rdf) return Promise.resolve($rdf);
        if (window.$rdf || window.rdflib) {
            $rdf = window.$rdf || window.rdflib;
            log("rdflib encontrada en window");
            return Promise.resolve($rdf);
        }
        return new Promise((resolve, reject) => {
            const src = 'https://cdn.jsdelivr.net/npm/rdflib/dist/rdflib.min.js';
            const s = document.createElement('script');
            s.src = src;
            s.async = true;
            s.onload = () => {
                $rdf = window.$rdf || window.rdflib;
                if ($rdf) {
                    log("rdflib cargada desde CDN");
                    resolve($rdf);
                } else {
                    reject(new Error('rdflib cargada pero window.rdflib no está definido'));
                }
            };
            s.onerror = () => reject(new Error('No se pudo cargar rdflib desde ' + src));
            document.head.appendChild(s);
        });
    }

    // Función de prueba rápida de fetch para que veas peticiones en Network y resultados en consola
    async function fetchTest(url) {
        try {
            log("fetchTest -> solicitando", url);
            const r = await fetch(url, { cache: "no-store" });
            log(`fetchTest -> ${url} status:`, r.status, r.statusText, "ok:", r.ok);
            return r;
        } catch (err) {
            log(`fetchTest -> error fetch ${url}:`, err);
            throw err;
        }
    }

    async function inicializarSistema() {
        actualizarStatus("INICIALIZANDO...");
        // Aviso si se abre con file:// (fetch normalmente no funciona)
        if (window.location.protocol === 'file:') {
            actualizarStatus("ERROR: usando file:// — usa un servidor local (ver consola)");
            log("AVISO: estás usando file:// — fetch puede fallar. Ejecuta un servidor local (p.ej. python -m http.server).");
            // continuamos para que veas logs, pero probablemente fetch falle
        }

        try {
            await ensureRdflib();
        } catch (err) {
            console.error("Error cargando rdflib:", err);
            actualizarStatus("ERROR: rdflib no disponible (ver consola)");
            return;
        }

        store = $rdf.graph();
        actualizarStatus("CARGANDO DATOS...");

        // Hacemos un fetchTest por cada archivo para forzar la petición y mostrarla en Network
        const keys = Object.keys(DATA_FILES);
        const results = [];
        for (const k of keys) {
            const path = DATA_FILES[k];
            try {
                const resp = await fetchTest(path);
                if (!resp.ok) {
                    results.push({ key: k, path, ok: false, status: resp.status });
                    continue;
                }
                const texto = await resp.text();
                try {
                    const base = new URL(path, window.location.href).href;
                    $rdf.parse(texto, store, base, path.endsWith('.rdf') ? 'application/rdf+xml' : 'text/turtle');
                    log("Parseado OK:", path);
                    results.push({ key: k, path, ok: true });
                } catch (parseErr) {
                    log("Error parseando", path, parseErr);
                    results.push({ key: k, path, ok: false, error: parseErr });
                }
            } catch (err) {
                results.push({ key: k, path, ok: false, error: err });
            }
        }

        const errores = results.filter(r => !r.ok);
        if (errores.length > 0) {
            console.error("Errores cargando/parseando archivos:", errores);
            actualizarStatus("ERROR CARGA DATOS (ver consola y Network)");
            const container = document.getElementById("resultados-grid");
            if (container) {
                container.innerHTML = `<p style="color:black; padding:20px;">
                    Error cargando ficheros. Revisa la pestaña Network y la consola.
                    Si abres el HTML con file://, inicia un servidor local (p.ej. python -m http.server).
                </p>`;
            }
            return;
        }

        actualizarStatus("SISTEMA ONLINE (MODO LOCAL)");
        log("Inicialización completa. Triples en store (si disponible):", store ? (store.length || "(size not available)") : "(no store)");
    }

    // llamado por botones
    window.ejecutarQuery = async function(id) {
        if (!store) {
            log("ejecutarQuery llamado pero store no inicializado. Llamando inicializarSistema...");
            await inicializarSistema();
            // si todavía no hay store, abortamos
            if (!store) {
                log("store sigue sin inicializar tras inicializarSistema()");
                return;
            }
        }

        let query = "";
        const inputElement = document.getElementById("cveInput");
        const valorBusqueda = inputElement ? inputElement.value.trim() : "";

        switch(id) {
            case 1:
                query = PREFIXES + `
                    SELECT ?vulnerabilidad ?score
                    WHERE {
                        ?vulnerabilidad a onto:Vulnerabilidad ;
                                       onto:evaluadaPor ?eval .
                        ?eval onto:tienePuntuacionCVSS ?score .
                    }`;
                break;
            case 2:
                query = PREFIXES + `
                    SELECT DISTINCT ?tecnicaLabel ?tacticaLabel
                    WHERE {
                        ?tecnica a onto:TecnicaAtaque ;
                                 onto:perteneceTactica ?tactica ;
                                 rdfs:label ?tecnicaLabel .
                        ?tactica rdfs:label ?tacticaLabel .
                    }`;
                break;
            case 3:
                query = PREFIXES + `
                    SELECT DISTINCT ?vulnerabilidad ?mitigacionNombre
                    WHERE {
                        ?vulnerabilidad a onto:Vulnerabilidad ;
                                        onto:mitigadaPor ?m .
                        ?m rdfs:label ?mitigacionNombre .
                    }`;
                break;
            case 4:
                if (!valorBusqueda) { alert("Introduce un CVE para buscar"); return; }
                query = PREFIXES + `
                    SELECT ?id ?descripcion ?score ?activo ?mitigacion
                    WHERE {
                        ?v a onto:Vulnerabilidad ;
                           onto:tieneCVE_ID ?id .
                        FILTER(str(?id) = "${valorBusqueda}")
                        OPTIONAL { ?v onto:tieneDescripcion ?descripcion . }
                        OPTIONAL { ?v onto:evaluadaPor ?e . ?e onto:tienePuntuacionCVSS ?score . }
                        OPTIONAL { ?v onto:afecta ?activo . }
                        OPTIONAL { ?v onto:mitigadaPor ?m . ?m rdfs:label ?mitigacion . }
                    } LIMIT 1`;
                break;
            default:
                log("Query id no soportado:", id);
                return;
        }

        realizarConsultaInterna(query, id);
    };

    async function realizarConsultaInterna(queryString, queryID) {
        const container = document.getElementById("resultados-grid");
        const loading = document.getElementById("loading");
        if (container) container.innerHTML = "";
        if (loading) loading.classList.remove("hidden");

        try {
            await ensureRdflib();
        } catch (err) {
            if (loading) loading.classList.add("hidden");
            console.error("rdflib no disponible:", err);
            if (container) container.innerHTML = "<p style='color:black; padding:20px;'>Error: librería RDF no disponible.</p>";
            return;
        }

        if (!store) {
            if (loading) loading.classList.add("hidden");
            console.error("Store no inicializado. Llama a inicializarSistema() antes.");
            if (container) container.innerHTML = "<p style='color:black; padding:20px;'>Error: datos RDF no cargados.</p>";
            return;
        }

        if (typeof $rdf.SPARQLToQuery !== 'function') {
            if (loading) loading.classList.add("hidden");
            console.error("SPARQLToQuery no está disponible en rdflib:", $rdf);
            if (container) container.innerHTML = "<p style='color:black; padding:20px;'>Error: función SPARQLToQuery no disponible en la librería rdflib cargada.</p>";
            return;
        }

        try {
            const q = $rdf.SPARQLToQuery(queryString, false, store);
            const results = [];
            store.query(q, (res) => results.push(res), null, () => {
                if (loading) loading.classList.add("hidden");
                // Procesado simple para queryID===1 (como antes)
                if (queryID === 1) {
                    const map = new Map();
                    results.forEach(res => {
                        const v = res['?vulnerabilidad'] ? res['?vulnerabilidad'].value : null;
                        const sRaw = res['?score'] ? res['?score'].value : null;
                        const sNum = sRaw !== null ? parseFloat(sRaw) : NaN;
                        if (!v) return;
                        const existing = map.get(v);
                        if (!existing || (!isNaN(sNum) && sNum > existing._scoreNum)) {
                            map.set(v, {
                                '?vulnerabilidad': { value: v },
                                '?score': { value: isNaN(sNum) ? (sRaw || "") : String(sNum) },
                                _scoreNum: isNaN(sNum) ? Number.NEGATIVE_INFINITY : sNum
                            });
                        }
                    });
                    const processed = Array.from(map.values())
                        .filter(entry => entry._scoreNum >= 9.5)
                        .sort((a, b) => b._scoreNum - a._scoreNum);
                    if (processed.length === 0) {
                        if (container) container.innerHTML = "<p style='color:black; padding:20px;'>No se encontraron vulnerabilidades con CVSS >= 9.5.</p>";
                        return;
                    }
                    renderizarResultados(processed, queryID);
                    return;
                }
                renderizarResultados(results, queryID);
            });
        } catch (err) {
            if (loading) loading.classList.add("hidden");
            console.error("Error en SPARQL:", err);
            if (container) container.innerHTML = "<p style='color:black; padding:20px;'>Error ejecutando la consulta SPARQL (mira consola).</p>";
        }
    }

    function renderizarResultados(results, queryID) {
        const container = document.getElementById("resultados-grid");
        if (!container) return;
        if (results.length === 0) {
            container.innerHTML = "<p style='color:black; padding:20px;'>No se encontraron resultados para esta consulta.</p>";
            return;
        }
        container.innerHTML = "";
        results.forEach((result) => {
            const div = document.createElement("div");
            div.className = "resultado-card";
            const get = (name) => result[`?${name}`] ? result[`?${name}`].value : null;
            const limpiar = (uri) => uri ? uri.split('/').pop().replace(/_/g, "-") : "";
            let html = "";
            if (queryID === 1) {
                html = `<h3 style="color:#0056b3; margin:0;">${limpiar(get('vulnerabilidad'))}</h3>
                        <p style="color:black;"><strong>CVSS:</strong> ${get('score')}</p>`;
            } else if (queryID === 2) {
                html = `<p style="color:black;"><strong>Técnica:</strong> ${get('tecnicaLabel')}</p>
                        <p style="color:black;"><strong>Táctica:</strong> ${get('tacticaLabel')}</p>`;
            } else if (queryID === 3) {
                html = `<p style="color:black;"><strong>Vulnerabilidad:</strong> ${limpiar(get('vulnerabilidad'))}</p>
                        <p style="color:black;"><strong>Mitigación:</strong> ${get('mitigacionNombre')}</p>`;
            } else if (queryID === 4) {
                html = `<h3 style="color:#0056b3; margin:0;">${get('id') ? get('id').replace(/_/g, "-") : "Detalles"}</h3>
                        <p style="color:black;"><strong>CVSS Score:</strong> ${get('score') || 'N/A'}</p>
                        <p style="color:black;"><strong>Descripción:</strong> ${get('descripcion') || 'No disponible'}</p>
                        <p style="color:black;"><strong>Activo Afectado:</strong> ${get('activo') ? limpiar(get('activo')) : 'N/A'}</p>
                        <p style="color:black;"><strong>Mitigación:</strong> ${get('mitigacion') || 'No definida'}</p>`;
            }
            div.innerHTML = html;
            container.appendChild(div);
        });
    }

    // auto-init cuando el DOM esté listo
    document.addEventListener('DOMContentLoaded', () => {
        log("DOM listo -> llamando inicializarSistema()");
        inicializarSistema().catch(err => {
            console.error("Error en inicializarSistema (no crítico):", err);
        });
    });

    // export
    window.inicializarSistema = inicializarSistema;
}