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

    let store;
    let $rdf;

    async function inicializarSistema() {
        $rdf = window.$rdf || window.rdflib;
        if (!$rdf) return;
        actualizarStatus("CARGANDO DATOS...");
        store = $rdf.graph();
        try {
            const cargar = async (url, formato) => {
                const res = await fetch(url);
                const texto = await res.text();
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
        } catch (e) { actualizarStatus("ERROR DE CARGA"); }
    }

    window.ejecutarQuery = function(id) {
        let query = "";
        // Capturamos el valor del input para la función 4
        const inputElement = document.getElementById("cveInput");
        const valorBusqueda = inputElement ? inputElement.value.trim() : "";

        switch(id) {
            case 1: // RIESGOS CRÍTICOS (procesado en JS para poder ordenar/filtrar numéricamente)
                // Nota: rdflib.js SPARQLToQuery / store.query no siempre respeta ORDER BY ni hace coerción numérica fiable.
                // Por eso traemos los pares (vulnerabilidad, score) y filtramos/ordenamos en JS.
                query = PREFIXES + `
                    SELECT ?vulnerabilidad ?score
                    WHERE {
                        ?vulnerabilidad a onto:Vulnerabilidad ;
                                       onto:evaluadaPor ?eval .
                        ?eval onto:tienePuntuacionCVSS ?score .
                    }`;
                break;

            case 2: // TÁCTICAS Y TÉCNICAS
                query = PREFIXES + `
                    SELECT DISTINCT ?tecnicaLabel ?tacticaLabel
                    WHERE {
                        ?tecnica a onto:TecnicaAtaque ;
                                 onto:perteneceTactica ?tactica ;
                                 rdfs:label ?tecnicaLabel .
                        ?tactica rdfs:label ?tacticaLabel .
                    }`;
                break;

            case 3: // MITIGACIONES
                query = PREFIXES + `
                    SELECT DISTINCT ?vulnerabilidad ?mitigacionNombre
                    WHERE {
                        ?vulnerabilidad a onto:Vulnerabilidad ;
                                        onto:mitigadaPor ?m .
                        ?m rdfs:label ?mitigacionNombre .
                    }`;
                break;

            case 4: // BUSCAR CVE (Tu código de GraphDB adaptado)
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
        realizarConsultaInterna(query, id);
    };

    function realizarConsultaInterna(queryString, queryID) {
        const container = document.getElementById("resultados-grid");
        const loading = document.getElementById("loading");
        container.innerHTML = "";
        if (loading) loading.classList.remove("hidden");

        try {
            const query = $rdf.SPARQLToQuery(queryString, false, store);
            const results = [];
            store.query(query, (res) => { results.push(res); }, null, () => {
                if (loading) loading.classList.add("hidden");

                // PROCESADO ESPECIAL PARA QUERY 1:
                // coerción numérica en SPARQL -> hacemos filter/orden en JS.
                if (queryID === 1) {
                    // Construimos un map por vulnerabilidad y nos quedamos con el score numérico más alto si hay duplicados.
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

                    // Filtramos por CVSS >= 9.5 y ordenamos descendente por puntuación numérica
                    const processed = Array.from(map.values())
                        .filter(entry => entry._scoreNum >= 9.5)
                        .sort((a, b) => b._scoreNum - a._scoreNum);

                    // Si no hay resultados después del filtrado mostramos mensaje
                    if (processed.length === 0) {
                        container.innerHTML = "<p style='color:black; padding:20px;'>No se encontraron vulnerabilidades con CVSS >= 9.5.</p>";
                        return;
                    }

                    renderizarResultados(processed, queryID);
                    return;
                }

                // Para el resto de queries: comportamiento original
                renderizarResultados(results, queryID);
            });
        } catch (err) {
            if (loading) loading.classList.add("hidden");
            console.error("Error en SPARQL:", err);
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
            
            // Función auxiliar para obtener el valor limpio
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
                // Formato especial para la búsqueda individual
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
}