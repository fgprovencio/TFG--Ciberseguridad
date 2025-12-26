{
    // 1. CONFIGURACIÓN
    const PREFIXES = `
        PREFIX onto: <http://www.tfguoc.org/ontologia/ciberseguridad/vulnerabilidades/>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
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

    // 2. INICIALIZACIÓN
    async function inicializarSistema() {
        $rdf = window.$rdf || window.rdflib;
        if (!$rdf) {
            actualizarStatus("ERROR: Librería rdflib no cargada.");
            return;
        }

        actualizarStatus("CARGANDO REPOSITORIO SEMÁNTICO...");
        store = $rdf.graph();
        
        try {
            const cargar = async (url, formato) => {
                const res = await fetch(url);
                if (!res.ok) throw new Error(`No se encontró ${url}`);
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
            actualizarStatus("ERROR DE CARGA: " + e.message);
            console.error(e);
        }
    }

    // 3. CONTROLADOR DE CONSULTAS
    window.ejecutarQuery = function(id) {
        let query = "";
        const cveInput = document.getElementById("cveInput")?.value.trim();

        switch(id) {
            case 1: // RIESGOS CRÍTICOS (Filtro >= 9.5 y Orden DESC)
                query = PREFIXES + `
                    SELECT DISTINCT ?cveID ?score
                    WHERE {
                        ?v a onto:Vulnerabilidad ;
                           onto:tieneCVE_ID ?cveID ;
                           onto:evaluadaPor ?eval .
                        ?eval onto:tienePuntuacionCVSS ?score .
                        FILTER(xsd:double(str(?score)) >= 9.5)
                    } ORDER BY DESC(xsd:double(str(?score)))`;
                break;

            case 2: // TÁCTICAS Y TÉCNICAS
                query = PREFIXES + `
                    SELECT DISTINCT ?tecnicaLabel ?tecnicaID ?tacticaLabel
                    WHERE {
                        ?tecnica a onto:TecnicaAtaque ;
                                 onto:perteneceTactica ?tactica ;
                                 rdfs:label ?tecnicaLabel .
                        ?tactica rdfs:label ?tacticaLabel .
                        BIND(STRAFTER(STR(?tecnica), "vulnerabilidades/") AS ?tecnicaID)
                    } ORDER BY ?tacticaLabel`;
                break;

            case 3: // MITIGACIONES
                query = PREFIXES + `
                    SELECT DISTINCT ?cveID ?mitigacionNombre
                    WHERE {
                        ?v a onto:Vulnerabilidad ;
                           onto:tieneCVE_ID ?cveID ;
                           onto:mitigadaPor ?m .
                        ?m rdfs:label ?mitigacionNombre .
                    } ORDER BY ?cveID`;
                break;

            case 4: // BÚSQUEDA POR CVE
                query = PREFIXES + `
                    SELECT DISTINCT ?cveID ?score ?descripcion ?activo ?mitigacion
                    WHERE {
                        ?v onto:tieneCVE_ID ?cveID .
                        FILTER(REGEX(str(?cveID), "^${cveInput}$", "i"))
                        OPTIONAL { ?v onto:tieneDescripcion ?descripcion . }
                        OPTIONAL { ?v onto:evaluadaPor ?e . ?e onto:tienePuntuacionCVSS ?score . }
                        OPTIONAL { ?v onto:afecta ?a . BIND(STRAFTER(STR(?a), "vulnerabilidades/") AS ?activo) }
                        OPTIONAL { ?v onto:mitigadaPor ?m . ?m rdfs:label ?mitigacion . }
                    } LIMIT 1`;
                break;
        }
        realizarConsultaInterna(query, id);
    };

    // 4. MOTOR SPARQL INTERNO
    function realizarConsultaInterna(queryString, queryID) {
        const container = document.getElementById("resultados-grid");
        const loading = document.getElementById("loading");
        
        if (!container) return;
        container.innerHTML = "";
        if (loading) loading.classList.remove("hidden");

        try {
            const query = $rdf.SPARQLToQuery(queryString, false, store);
            const results = [];
            
            store.query(query, 
                (res) => { results.push(res); }, 
                null, 
                () => {
                    if (loading) loading.classList.add("hidden");
                    renderizarResultados(results, queryID);
                }
            );
        } catch (err) {
            if (loading) loading.classList.add("hidden");
            container.innerHTML = `<p style="color:red">Error: ${err.message}</p>`;
        }
    }

    // 5. RENDERIZADO DE RESULTADOS (CORREGIDO)
    function renderizarResultados(results, queryID) {
        const container = document.getElementById("resultados-grid");
        if (results.length === 0) {
            container.innerHTML = "<p style='color:black;'>No se encontraron resultados.</p>";
            return;
        }

        results.forEach((result) => {
            const div = document.createElement("div");
            div.className = "resultado-card";
            div.style.backgroundColor = "#ffffff";
            div.style.border = "1px solid #ddd";
            div.style.borderLeft = "6px solid #0056b3";
            div.style.padding = "15px";
            div.style.marginBottom = "15px";
            div.style.borderRadius = "8px";
            div.style.color = "#000000"; // Forzamos texto negro

            let html = "";
            
            // Limpieza de datos (quitar ? y formatear CVE)
            let d = {};
            for (let k in result) {
                let key = k.replace('?', '');
                let val = result[k].value;
                if (key === 'cveID') val = val.replace(/_/g, "-");
                d[key] = val;
            }

            // Lógica por Función
            if (queryID === 1) {
                html = `<h3 style="margin:0; color:#0056b3;">${d.cveID}</h3>
                        <p style="margin:5px 0; color:black;"><strong>CVSS:</strong> ${d.score}</p>`;
            } 
            else if (queryID === 2) {
                html = `<p style="margin:5px 0; color:black;"><strong>Técnica:</strong> ${d.tecnicaLabel} (${d.tecnicaID})</p>
                        <p style="margin:5px 0; color:black;"><strong>Táctica:</strong> ${d.tacticaLabel}</p>`;
            } 
            else if (queryID === 3) {
                html = `<p style="margin:5px 0; color:black;"><strong>Vulnerabilidad:</strong> ${d.cveID}</p>
                        <p style="margin:5px 0; color:black;"><strong>Mitigación:</strong> ${d.mitigacionNombre}</p>`;
            }
            else {
                // Función 4 o Genérica
                html = `<h3 style="margin:0; color:#0056b3;">${d.cveID || 'Resultado'}</h3>`;
                for (let key in d) {
                    if (key !== 'cveID') {
                        let label = key.toUpperCase();
                        html += `<p style="margin:5px 0; color:black;"><strong>${label}:</strong> ${d[key]}</p>`;
                    }
                }
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