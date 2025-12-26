{
    // 1. CONFIGURACIÓN DE RUTAS Y PREFIJOS
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

    // 2. INICIALIZACIÓN (Se ejecuta al cargar la página)
    async function inicializarSistema() {
        // Intentamos detectar la librería de ambas formas posibles
        $rdf = window.$rdf || window.rdflib;

        if (!$rdf) {
            actualizarStatus("ERROR: No se encontró rdflib.min.js");
            console.error("Librería rdflib no detectada.");
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

            // Cargamos todos los archivos en la memoria del navegador
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
            console.error(e);
        }
    }

    // 3. FUNCIONES 
    window.ejecutarQuery = function(id) {
        let query = "";
        const cveInput = document.getElementById("cveInput")?.value;

        switch(id) {
            case 1: // Riesgos Críticos
                query = PREFIXES + `
                    SELECT ?cveID ?score
                    WHERE {
                        ?v a onto:Vulnerabilidad ;
                            onto:tieneCVE_ID ?cveID ;
                            onto:evaluadaPor ?eval .
                        ?eval onto:tienePuntuacionCVSS ?score .
                        FILTER(xsd:double(str(?score)) >= 9.5)
                    } ORDER BY DESC(?score)`;
                break;
            case 2: // Tácticas y Técnicas
                query = PREFIXES + `
                    SELECT ?tacticaLabel ?tecnicaLabel ?tecnicaID
                    WHERE {
                        ?tecnica a onto:TecnicaAtaque ;
                                onto:perteneceTactica ?tactica ;
                                rdfs:label ?tecnicaLabel .
                        ?tactica rdfs:label ?tacticaLabel .
                        BIND(STRAFTER(STR(?tecnica), "vulnerabilidades/") AS ?tecnicaID)
                    } ORDER BY ?tacticaLabel`;
            case 3: // Mitigaciones
                query = PREFIXES + `
                    SELECT ?cveID ?mitigacionNombre
                    WHERE {
                        ?v a onto:Vulnerabilidad ;
                            onto:tieneCVE_ID ?cveID ;
                            onto:mitigadaPor ?m .
                        ?m rdfs:label ?mitigacionNombre .
                    } ORDER BY ?cveID`;
                break;
            case 4: // Buscar por CVE
                query = PREFIXES + `
                    SELECT ?descripcion ?score ?activo ?mitigacion
                    WHERE {
                        ?v a onto:Vulnerabilidad ;
                           onto:tieneCVE_ID ?id .
                        FILTER(REGEX(str(?id), "^${cveInput}$", "i"))
                        OPTIONAL { ?v onto:tieneDescripcion ?descripcion . }
                        OPTIONAL { ?v onto:evaluadaPor ?e . ?e onto:tienePuntuacionCVSS ?score . }
                        OPTIONAL { ?v onto:afecta ?activo . }
                        OPTIONAL { ?v onto:mitigadaPor ?mitigacion . }
                    } LIMIT 1`;
                break;
        }
        realizarConsultaInterna(query);
    };

    // 4. MOTOR DE CONSULTA 
    function realizarConsultaInterna(queryString) {
        const container = document.getElementById("resultados-grid");
        const loading = document.getElementById("loading");
        
        container.innerHTML = "";
        loading.classList.remove("hidden");

        try {
            const query = $rdf.SPARQLToQuery(queryString, false, store);
            const results = [];
            
            store.query(query, 
                (res) => { results.push(res); }, 
                null, 
                () => {
                    loading.classList.add("hidden");
                    renderizarResultados(results);
                }
            );
        } catch (err) {
            loading.classList.add("hidden");
            container.innerHTML = `<p style="color:red">Error en motor: ${err.message}</p>`;
        }
    }

    // 5. LÓGICA DE FORMATEO
    function formatearNombreURI(val, key) {
        if (!val) return "";
    
        // Si es un CVE, cambiamos guiones bajos por guiones medios: CVE_2023 -> CVE-2023
        if (key.toLowerCase().includes("cve")) {
            return val.replace(/_/g, "-");
        }

        // Si es una URI larga, nos quedamos con el final
        if (val.includes("http")) {
            val = val.split("#").pop().split("/").pop();
        }

        // Separar CamelCase (DobleFactor -> Doble Factor)
        return val.replace(/([a-z])([A-Z])/g, "$1 $2");
    }

    function renderizarResultados(results) {
        const container = document.getElementById("resultados-grid");
        container.innerHTML = "";

        results.forEach((result) => {
            const div = document.createElement("div");
            div.className = "resultado-card";

            let html = "";
        
            // Lógica personalizada según el tipo de datos que vengan
            if (result.tecnicaLabel && result.tacticaLabel) {
                // Caso 2: Técnicas y Tácticas
                html += `<p><strong>Técnica:</strong> ${result.tecnicaLabel.value} (${result.tecnicaID.value})</p>`;
                html += `<p><strong>Táctica:</strong> ${result.tacticaLabel.value}</p>`;
            } 
            else if (result.cveID && result.mitigacionNombre) {
                // Caso 3: Mitigaciones
                html += `<p><strong>Vulnerabilidad:</strong> ${formatearNombreURI(result.cveID.value, 'cve')}</p>`;
                html += `<p><strong>Mitigación:</strong> ${result.mitigacionNombre.value}</p>`;
            }
            else if (result.cveID && result.score) {
                // Caso 1: Riesgos Críticos
                html += `<p><strong>CVSS:</strong> ${result.score.value}</p>`;
                html += `<p><strong>CVE:</strong> ${formatearNombreURI(result.cveID.value, 'cve')}</p>`;
            }
            else {
                // Caso genérico para búsqueda manual o otros
                for (const [key, obj] of Object.entries(result)) {
                    let etiqueta = key.replace("Label", "").replace("ID", "").toUpperCase();
                    html += `<p><strong>${etiqueta}:</strong> ${formatearNombreURI(obj.value, key)}</p>`;
                }
            }

            div.innerHTML = html;
            container.appendChild(div);
        });

    }

    // Utilidades de la interfaz
    function actualizarStatus(msg) {
        const s = document.getElementById('status-bar');
        if(s) s.innerText = `> ${msg}`;
    }

    window.prepararQuery4 = function() {
        document.getElementById('cve-search-box').classList.toggle('hidden');
    };

    // Arrancamos todo al cargar la ventana
    window.onload = inicializarSistema;
}