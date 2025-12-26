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

    // Asegura que rdflib esté disponible. Si no lo está, lo carga desde CDN.
    function ensureRdflib() {
        if ($rdf) return Promise.resolve($rdf);
        if (window.$rdf || window.rdflib) {
            $rdf = window.$rdf || window.rdflib;
            return Promise.resolve($rdf);
        }
        return new Promise((resolve, reject) => {
            const src = 'https://cdn.jsdelivr.net/npm/rdflib/dist/rdflib.min.js';
            const s = document.createElement('script');
            s.src = src;
            s.async = true;
            s.onload = () => {
                $rdf = window.$rdf || window.rdflib;
                if ($rdf) resolve($rdf);
                else reject(new Error('rdflib cargado pero window.rdflib no está definido'));
            };
            s.onerror = () => reject(new Error('No se pudo cargar rdflib desde ' + src));
            document.head.appendChild(s);
        });
    }

    async function inicializarSistema() {
        try {
            await ensureRdflib();
        } catch (err) {
            console.error("No se pudo cargar rdflib:", err);
            actualizarStatus("ERROR: librería rdflib no disponible");
            return;
        }

        actualizarStatus("CARGANDO DATOS...");
        store = $rdf.graph();
        try {
            const cargar = async (url, formato) => {
                const res = await fetch(url);
                const texto = await res.text();
                // usar la URL base correcta (puedes pasar window.location.href o la propia url)
                $rdf.parse(texto, store, window.location.href, formato);
            };
            await Promise.all([
                cargar(DATA_FILES.ontologia, 'application/rdf+xml'),
                cargar(DATA_FILES.nvd1, 'text/turtle'),
                cargar(DATA_FILES.nvd2, 'text/turtle'),
                cargar(DATA_FILES.mitre, 'text/turtle'),
                cargar(DATA_FILES.mitigaciones, 'text/turtle')
            ]);
            actualizarStatus("SISTEMA ONLINE (MODO LOCAL)");
        } catch (e) {
            console.error("Error cargando datos RDF:", e);
            actualizarStatus("ERROR DE CARGA");
        }
    }

    window.ejecutarQuery = function(id) {
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
                if (!valorBusqueda) {
                    alert("Introduce un CVE para buscar");
                    return;
                }
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
        }
        // llamar a la función asíncrona (no necesitamos await aquí)
        realizarConsultaInterna(query, id);
    };

    // Ahora es asíncrona para poder asegurar rdflib antes de usar SPARQLToQuery
    async function realizarConsultaInterna(queryString, queryID) {
        const container = document.getElementById("resultados-grid");
        const loading = document.getElementById("loading");
        container.innerHTML = "";
        if (loading) loading.classList.remove("hidden");

        try {
            await ensureRdflib();
        } catch (err) {
            if (loading) loading.classList.add("hidden");
            console.error("rdflib no disponible:", err);
            container.innerHTML = "<p style='color:black; padding:20px;'>Error: librería RDF no disponible.</p>";
            return;
        }

        if (!store) {
            if (loading) loading.classList.add("hidden");
            container.innerHTML = "<p style='color:black; padding:20px;'>Error: datos RDF no cargados. Ejecuta la inicialización.</p>";
            return;
        }

        if (typeof $rdf.SPARQLToQuery !== 'function') {
            if (loading) loading.classList.add("hidden");
            console.error("SPARQLToQuery no está disponible en rdflib:", $rdf);
            container.innerHTML = "<p style='color:black; padding:20px;'>Error: función SPARQLToQuery no disponible en la librería rdflib cargada.</p>";
            return;
        }

        try {
            const query = $rdf.SPARQLToQuery(queryString, false, store);
            const results = [];
            store.query(query, (res) => { results.push(res); }, null, () => {
                if (loading) loading.classList.add("hidden");

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
                        container.innerHTML = "<p style='color:black; padding:20px;'>No se encontraron vulnerabilidades con CVSS >= 9.5.</p>";
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
            container.innerHTML = "<p style='color:black; padding:20px;'>Error ejecutando la consulta SPARQL (mira consola).</p>";
        }
    }

    function renderizarResultados(results, queryID) {
        const container = document.getElementById("resultados-grid");
        if (results.length === 0) {
            container.innerHTML = "<p style='color:black; padding:20px;'>No se encontraron resultados para esta consulta.</p>";
            return;
        }

        results.forEach((result) => {
            const div = document.createElement("div");
            div.className = "resultado-card";
            
            const get = (name) => result[`?${name}`] ? result[`?${name}`].value : null;
            const limpiar = (uri) => uri ? uri.split('/').pop().replace(/_/g, "-") : "";

            let html = "";
            if (queryID === 1) {
                html = `<h3 style="color:#0056b3; margin:0;">${limpiar(get('vulnerabilidad'))}</h3>
                        <p style="color:black;"><strong>CVSS:</strong> ${get('score')}</p>`;
            } 
            else if (queryID === 2) {
                html = `<p style="color:black;"><strong>Técnica:</strong> ${get('tecnicaLabel')}</p>
                        <p style="color:black;"><strong>Táctica:</strong> ${get('tacticaLabel')}</p>`;
            } 
            else if (queryID === 3) {
                html = `<p style="color:black;"><strong>Vulnerabilidad:</strong> ${limpiar(get('vulnerabilidad'))}</p>
                        <p style="color:black;"><strong>Mitigación:</strong> ${get('mitigacionNombre')}</p>`;
            } 
            else if (queryID === 4) {
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

    // Exponer inicialización para que la llames desde el onload de la página
    window.inicializarSistema = inicializarSistema;
}