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
	mitigaciones: './data/mitigaciones_manual.ttl',
    };

    let store;
    let $rdf;

    async function inicializarSistema() {
        $rdf = window.$rdf || window.rdflib;
        if (!$rdf) return;
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
            document.getElementById('status-bar').innerText = "> SISTEMA ONLINE";
        } catch (e) { console.error(e); }
    }

    window.ejecutarQuery = function(id) {
        let query = "";
        const cveInput = document.getElementById("cveInput")?.value.trim().toUpperCase() || "";

        switch(id) {
            case 1: // RIESGOS CRÍTICOS: Pedimos todas las que tengan puntuación
                query = PREFIXES + `
                    SELECT DISTINCT ?v ?score
                    WHERE {
                        ?v a onto:Vulnerabilidad ;
                           onto:evaluadaPor ?e .
                        ?e onto:tienePuntuacionCVSS ?score .
                    }`;
                break;

            case 4: // BUSCAR CVE: Pedimos todas las que tengan ID para filtrar en JS
                query = PREFIXES + `
                    SELECT DISTINCT ?id ?score ?desc
                    WHERE {
                        ?v a onto:Vulnerabilidad ;
                           onto:tieneCVE_ID ?id .
                        OPTIONAL { ?v onto:tieneDescripcion ?desc . }
                        OPTIONAL { ?v onto:evaluadaPor ?e . ?e onto:tienePuntuacionCVSS ?score . }
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
                    SELECT DISTINCT ?id ?mitigacionNombre
                    WHERE {
                        ?v a onto:Vulnerabilidad ;
                           onto:tieneCVE_ID ?id ;
                           onto:mitigadaPor ?m .
                        ?m rdfs:label ?mitigacionNombre .
                    }`;
                break;
        }
        realizarConsultaInterna(query, id, cveInput);
    };

    function realizarConsultaInterna(queryString, queryID, filtroTexto) {
        const container = document.getElementById("resultados-grid");
        container.innerHTML = "";

        try {
            const query = $rdf.SPARQLToQuery(queryString, false, store);
            const results = [];
            store.query(query, (res) => { results.push(res); }, null, () => {
                // Aquí aplicamos el filtrado inteligente de JS
                procesarYMostrar(results, queryID, filtroTexto);
            });
        } catch (err) { console.error(err); }
    }

    function procesarYMostrar(results, queryID, filtroTexto) {
        const container = document.getElementById("resultados-grid");
        
        // Mapeamos los resultados a objetos simples de JS
        let datos = results.map(r => {
            let obj = {};
            for (let key in r) { obj[key.replace('?', '')] = r[key].value; }
            return obj;
        });

        let finalData = [];

        // --- LÓGICA DE FILTRADO JS ---
        if (queryID === 1) {
            // Filtramos numéricamente: puntuación >= 9.5 y ordenamos
            finalData = datos.filter(d => parseFloat(d.score) >= 9.5)
                             .sort((a, b) => parseFloat(b.score) - parseFloat(a.score));
        } 
        else if (queryID === 4) {
            // Filtramos por coincidencia exacta de texto
            finalData = datos.filter(d => d.id.toUpperCase() === filtroTexto);
        } 
        else {
            finalData = datos;
        }

        if (finalData.length === 0) {
            container.innerHTML = "<p style='color:black; padding:20px;'>No se han encontrado resultados.</p>";
            return;
        }

        // --- RENDERIZADO ---
        finalData.forEach(d => {
            const div = document.createElement("div");
            div.className = "resultado-card";
            div.style.borderLeft = "6px solid #0056b3";
            div.style.padding = "15px";
            div.style.marginBottom = "10px";
            div.style.backgroundColor = "white";

            let html = "";
            const limpiar = (uri) => uri.includes('/') ? uri.split('/').pop().replace(/_/g, "-") : uri;

            if (queryID === 1) {
                html = `<h3 style="color:#0056b3; margin:0;">${limpiar(d.v)}</h3>
                        <p style="color:black;"><strong>CVSS:</strong> ${d.score}</p>`;
            } 
            else if (queryID === 4) {
                html = `<h3 style="color:#0056b3; margin:0;">${d.id}</h3>
                        <p style="color:black;"><strong>Puntuación:</strong> ${d.score || 'N/A'}</p>
                        <p style="color:black;"><strong>Descripción:</strong> ${d.desc || 'Sin descripción'}</p>`;
            }
            else if (queryID === 2) {
                html = `<p style="color:black;"><strong>Técnica:</strong> ${d.tecnicaLabel}</p>
                        <p style="color:black;"><strong>Táctica:</strong> ${d.tacticaLabel}</p>`;
            }
            else if (queryID === 3) {
                html = `<p style="color:black;"><strong>Vulnerabilidad:</strong> ${d.id}</p>
                        <p style="color:black;"><strong>Mitigación:</strong> ${d.mitigacionNombre}</p>`;
            }

            div.innerHTML = html;
            container.appendChild(div);
        });
    }

    window.onload = inicializarSistema;
}