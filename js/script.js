{
    // 1. Prefijos según tu ontología (usando el namespace oficial)
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
        actualizarStatus("CARGANDO REPOSITORIO...");
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
		cargar(DATA_FILES.mitigaciones, 'text/turtle'),
            ]);
            actualizarStatus("SISTEMA ONLINE");
        } catch (e) { actualizarStatus("ERROR DE CARGA"); }
    }

    window.ejecutarQuery = function(id) {
        let query = "";
        // Capturamos el input justo cuando se hace clic
        const inputBusqueda = document.getElementById("cveInput")?.value.trim() || "";

        switch(id) {
            case 1: // RIESGOS CRÍTICOS (Filtro numérico forzado)
                query = PREFIXES + `
                    SELECT DISTINCT ?v ?score
                    WHERE {
                        ?v a onto:Vulnerabilidad ;
                           onto:evaluadaPor ?e .
                        ?e onto:tienePuntuacionCVSS ?score .
                        FILTER(xsd:double(str(?score)) >= 9.5)
                    } ORDER BY DESC(xsd:double(str(?score)))`;
                break;

            case 4: // BUSCAR CVE (Filtro de texto exacto forzado)
                if (!inputBusqueda) {
                    alert("Por favor, escribe un CVE (ej: CVE-2024-0001)");
                    return;
                }
                query = PREFIXES + `
                    SELECT DISTINCT ?id ?score ?desc ?v
                    WHERE {
                        ?v a onto:Vulnerabilidad ;
                           onto:tieneCVE_ID ?id .
                        FILTER(str(?id) = "${inputBusqueda}")
                        OPTIONAL { ?v onto:tieneDescripcion ?desc . }
                        OPTIONAL { ?v onto:evaluadaPor ?e . ?e onto:tienePuntuacionCVSS ?score . }
                    } LIMIT 1`;
                break;

            case 2: // TÁCTICAS Y TÉCNICAS (Simplificada)
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
                    SELECT DISTINCT ?id ?mitigacionNombre
                    WHERE {
                        ?v a onto:Vulnerabilidad ;
                           onto:tieneCVE_ID ?id ;
                           onto:mitigadaPor ?m .
                        ?m rdfs:label ?mitigacionNombre .
                    }`;
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
            console.error("Error SPARQL:", err);
        }
    }

    function renderizarResultados(results, queryID) {
        const container = document.getElementById("resultados-grid");
        if (results.length === 0) {
            container.innerHTML = "<p style='color:black; padding:20px;'>No se han encontrado resultados con esos criterios.</p>";
            return;
        }

        results.forEach((result) => {
            const div = document.createElement("div");
            div.className = "resultado-card";
            
            // Función para extraer el valor de la variable ?nombre
            const get = (name) => result[`?${name}`] ? result[`?${name}`].value : "";
            const formatear = (val) => val.includes('/') ? val.split('/').pop().replace(/_/g, "-") : val;

            let html = "";
            if (queryID === 1) {
                html = `<h3 style="color:#0056b3; margin:0;">${formatear(get('v'))}</h3>
                        <p style="color:black; margin:5px 0;"><strong>CVSS:</strong> ${get('score')}</p>`;
            } 
            else if (queryID === 4) {
                html = `<h3 style="color:#0056b3; margin:0;">${get('id')}</h3>
                        <p style="color:black; margin:5px 0;"><strong>Puntuación CVSS:</strong> ${get('score') || 'Sin evaluar'}</p>
                        <p style="color:black; margin:5px 0;"><strong>Descripción:</strong> ${get('desc') || 'Sin descripción.'}</p>`;
            }
            else if (queryID === 2) {
                html = `<p style="color:black;"><strong>Técnica:</strong> ${get('tecnicaLabel')}</p>
                        <p style="color:black;"><strong>Táctica:</strong> ${get('tacticaLabel')}</p>`;
            }
            else if (queryID === 3) {
                html = `<p style="color:black;"><strong>Vulnerabilidad:</strong> ${get('id')}</p>
                        <p style="color:black;"><strong>Mitigación:</strong> ${get('mitigacionNombre')}</p>`;
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