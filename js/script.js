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
        } catch (e) {
            actualizarStatus("ERROR DE CARGA");
        }
    }

    window.ejecutarQuery = function(id) {
        let query = "";
        const cveInput = document.getElementById("cveInput")?.value.trim() || "";

        switch(id) {
            case 1: // RIESGOS CRÍTICOS (Copiada de tu GraphDB)
                query = PREFIXES + `
                    SELECT ?vulnerabilidad ?score
                    WHERE {
                        ?vulnerabilidad a onto:Vulnerabilidad ;
                                        onto:evaluadaPor ?eval .
                        ?eval onto:tienePuntuacionCVSS ?score .
                        FILTER(?score >= 9.5)
                    }
                    ORDER BY DESC(?score)`;
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

            case 4: // BUSCAR CVE (Corregido para filtrar de verdad)
                query = PREFIXES + `
                    SELECT ?vulnerabilidad ?score ?descripcion
                    WHERE {
                        ?vulnerabilidad a onto:Vulnerabilidad .
                        ?vulnerabilidad onto:tieneCVE_ID ?id .
                        FILTER(str(?id) = "${cveInput}")
                        OPTIONAL { ?vulnerabilidad onto:tieneDescripcion ?descripcion . }
                        OPTIONAL { ?vulnerabilidad onto:evaluadaPor ?e . ?e onto:tienePuntuacionCVSS ?score . }
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
                renderizarResultados(results, queryID);
            });
        } catch (err) {
            if (loading) loading.classList.add("hidden");
            console.error(err);
        }
    }

    function renderizarResultados(results, queryID) {
        const container = document.getElementById("resultados-grid");
        if (results.length === 0) {
            container.innerHTML = "<p style='color:black; padding:20px;'>No se encontraron resultados.</p>";
            return;
        }

        results.forEach((result) => {
            const div = document.createElement("div");
            div.className = "resultado-card";
            
            // Extraer valores limpios
            const getVal = (key) => result[`?${key}`] ? result[`?${key}`].value : "";
            
            // Función para limpiar la URI y dejar solo el CVE (ej: CVE-2024-0001)
            const limpiarCVE = (uri) => uri.split('/').pop().replace(/_/g, "-");

            let html = "";
            if (queryID === 1) {
                html = `<h3 style="color:#0056b3; margin:0;">${limpiarCVE(getVal('vulnerabilidad'))}</h3>
                        <p style="color:black; margin:5px 0;"><strong>CVSS:</strong> ${getVal('score')}</p>`;
            } else if (queryID === 2) {
                html = `<p style="color:black; margin:5px 0;"><strong>Técnica:</strong> ${getVal('tecnicaLabel')}</p>
                        <p style="color:black; margin:5px 0;"><strong>Táctica:</strong> ${getVal('tacticaLabel')}</p>`;
            } else if (queryID === 3) {
                html = `<p style="color:black; margin:5px 0;"><strong>Vulnerabilidad:</strong> ${limpiarCVE(getVal('vulnerabilidad'))}</p>
                        <p style="color:black; margin:5px 0;"><strong>Mitigación:</strong> ${getVal('mitigacionNombre')}</p>`;
            } else {
                html = `<h3 style="color:#0056b3; margin:0;">${limpiarCVE(getVal('vulnerabilidad'))}</h3>
                        <p style="color:black; margin:5px 0;"><strong>CVSS:</strong> ${getVal('score') || 'N/A'}</p>
                        <p style="color:black; margin:5px 0;"><strong>Descripción:</strong> ${getVal('descripcion')}</p>`;
            }

            div.innerHTML = html;
            container.appendChild(div);
        });
    }

    function actualizarStatus(msg) {
        const s = document.getElementById('status-bar');
        if(s) s.innerText = `> ${msg}`;
    }

    window.onload = inicializarSistema;
}