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
            actualizarStatus("ERROR DE CARGA");
        }
    }

    window.ejecutarQuery = function(id) {
        let query = "";
        // Capturamos el input de búsqueda
        const rawInput = document.getElementById("cveInput")?.value || "";
        const cveInput = rawInput.trim();

        switch(id) {
            case 1: // RIESGOS CRÍTICOS (Corregido: Forzamos Double para el filtro)
                query = PREFIXES + `
                    SELECT DISTINCT ?cveID ?score
                    WHERE {
                        ?v a onto:Vulnerabilidad ;
                           onto:tieneCVE_ID ?cveID ;
                           onto:evaluadaPor ?e .
                        ?e onto:tienePuntuacionCVSS ?score .
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

            case 4: // BUSCAR CVE (Corregido: Filtro de coincidencia exacta)
                if(!cveInput) {
                    alert("Por favor, introduce un CVE (ej: CVE-2024-0001)");
                    return;
                }
                query = PREFIXES + `
                    SELECT DISTINCT ?cveID ?score ?descripcion
                    WHERE {
                        ?v a onto:Vulnerabilidad ;
                           onto:tieneCVE_ID ?cveID .
                        OPTIONAL { ?v onto:tieneDescripcion ?descripcion . }
                        OPTIONAL { ?v onto:evaluadaPor ?e . ?e onto:tienePuntuacionCVSS ?score . }
                        FILTER(str(?cveID) = "${cveInput}")
                    } LIMIT 1`;
                break;
        }
        realizarConsultaInterna(query, id);
    };

    function realizarConsultaInterna(queryString, queryID) {
        const container = document.getElementById("resultados-grid");
        const loading = document.getElementById("loading");
        if (!container) return;
        
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
            container.innerHTML = "<p style='color:black; padding:20px;'>No se encontraron resultados para los criterios seleccionados.</p>";
            return;
        }

        results.forEach((result) => {
            const div = document.createElement("div");
            div.className = "resultado-card";
            
            // Limpiar variables del objeto result
            let d = {};
            for (let k in result) {
                let key = k.replace('?', '');
                d[key] = result[k].value;
            }

            let html = "";
            const cveFormateado = d.cveID ? d.cveID.replace(/_/g, "-") : "CVE Desconocido";

            if (queryID === 1) {
                html = `<h3 style="color:#0056b3; margin:0;">${cveFormateado}</h3>
                        <p style="color:black; margin:5px 0;"><strong>CVSS:</strong> ${d.score}</p>`;
            } 
            else if (queryID === 2) {
                html = `<p style="color:black; margin:5px 0;"><strong>Técnica:</strong> ${d.tecnicaLabel} (${d.tecnicaID})</p>
                        <p style="color:black; margin:5px 0;"><strong>Táctica:</strong> ${d.tacticaLabel}</p>`;
            } 
            else if (queryID === 3) {
                html = `<p style="color:black; margin:5px 0;"><strong>Vulnerabilidad:</strong> ${cveFormateado}</p>
                        <p style="color:black; margin:5px 0;"><strong>Mitigación:</strong> ${d.mitigacionNombre}</p>`;
            }
            else { // Caso 4: Búsqueda
                html = `<h3 style="color:#0056b3; margin:0;">${cveFormateado}</h3>
                        <p style="color:black; margin:5px 0;"><strong>CVSS:</strong> ${d.score || 'N/A'}</p>
                        <p style="color:black; margin:5px 0;"><strong>Descripción:</strong> ${d.descripcion || 'Sin descripción disponible.'}</p>`;
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