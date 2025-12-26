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
        nvd: './data/nvd_data.ttl',
        mitre: './data/mitre_data.ttl'
	mitigaciones: './data/mitigaciones_manual.ttl'
    };

    let store;
    let $rdf = window.$rdf;

    // 2. INICIALIZACIÓN (Se ejecuta al cargar la página)
    async function inicializarSistema() {
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
                cargar(DATA_FILES.nvd, 'text/turtle'),
                cargar(DATA_FILES.mitre, 'text/turtle')
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
                    SELECT ?vulnerabilidad ?score
                    WHERE {
                        ?vulnerabilidad a onto:Vulnerabilidad ;
                                        onto:evaluadaPor ?eval .
                        ?eval onto:tienePuntuacionCVSS ?score .
                        FILTER(xsd:double(str(?score)) >= 9.5)
                    } ORDER BY DESC(?score)`;
                break;
            case 2: // Tácticas y Técnicas
                query = PREFIXES + `
                    SELECT ?tacticaLabel ?tecnica ?tecnicaLabel
                    WHERE {
                        ?tecnica a onto:TecnicaAtaque ;
                                 onto:perteneceTactica ?tactica ;
                                 rdfs:label ?tecnicaLabel .
                        ?tactica rdfs:label ?tacticaLabel .
                    } ORDER BY ?tacticaLabel`;
                break;
            case 3: // Mitigaciones
                query = PREFIXES + `
                    SELECT ?vulnerabilidad ?mitigacion
                    WHERE {
                        ?vulnerabilidad a onto:Vulnerabilidad ;
                                        onto:mitigadaPor ?mitigacion .
                    } ORDER BY ?vulnerabilidad`;
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
    function formatearNombreURI(uri) {
        if (!uri) return "";
        let nombre = uri.split("#").pop().split("/").pop();
        nombre = nombre.replace(/([a-z])([A-Z])/g, "$1 $2");
        return nombre;
    }

    function renderizarResultados(results) {
        const container = document.getElementById("resultados-grid");
        
        if (results.length === 0) {
            container.innerHTML = "<p>No se encontraron resultados.</p>";
            return;
        }

        results.forEach((result) => {
            const div = document.createElement("div");
            div.className = "resultado-card"; // Usamos tu clase de CSS

            let contenido = "";
            for (const [key, value] of Object.entries(result)) {
                let val = value.value || "";
                // Aplicamos tu formateo a las columnas que son URIs
                if (["vulnerabilidad", "mitigacion", "tecnica", "tacticaLabel", "activo"].includes(key)) {
                    val = formatearNombreURI(val);
                }
                let etiqueta = key.charAt(0).toUpperCase() + key.slice(1);
                if (key === "score") etiqueta = "CVSS";
                
                contenido += `<p><strong>[${etiqueta}]:</strong> ${val}</p>`;
            }

            div.innerHTML = contenido;
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