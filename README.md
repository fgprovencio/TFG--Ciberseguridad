# TFG - Ciberseguridad Semántica

<p align="center">
  <img src="https://img.shields.io/badge/Reasoner-Pellet_Active-red?style=for-the-badge&logo=probot" alt="Reasoner Status">
  <img src="https://img.shields.io/badge/Ontology-OWL_DL-blue?style=for-the-badge&logo=w3c" alt="Ontology Type">
  <img src="https://img.shields.io/badge/Deployment-GitHub_Pages-green?style=for-the-badge&logo=githubpages" alt="Deployment">
</p>

## 🛡️ Web Semántica para el Análisis de Vulnerabilidades en Ciberseguridad

Este proyecto forma parte del **Trabajo Fin de Grado (TFG) en Ingeniería Informática**. Su objetivo principal es el diseño, implementación y explotación de una **ontología avanzada de ciberseguridad**, junto con un **Dashboard de Control Inteligente** que automatiza la ingesta, inferencia semántica y correlación cruzada de amenazas sin necesidad de consultar bases de datos relacionales tradicionales.

El sistema unifica el conocimiento extraído de estándares de la industria, mapeando de forma nativa datos de la **NVD (National Vulnerability Database)**, taxonomías **CWE (Common Weakness Enumeration)** y matrices de ataque **MITRE ATT&CK & CAPEC**.

---

## 🌐 Descripción General

La saturación de alertas y la dispersión de datos sobre amenazas dificultan la prevención de incidentes. Este proyecto propone un enfoque semántico en el que el conocimiento se conecta de forma lógica:

* **Ontología OWL (Abox y Tbox):** Modelado formal y semántico de *Threat Actors*, *Malware*, *Software Assets*, *Attack Patterns* y *Vulnerabilities (CVE)*.
* **Secuencia de Procesamiento de Ingesta Automatizado (Python + RDFLib):** Un motor extractor parsea los grafos triplicados en formato Turtle/XML, interactúa con el modelo ontológico y extrae las relaciones complejas e indirectas.
* **Razonamiento Lógico Automático:** Implementación de reglas de inferencia semántica y axiomas de severidad para clasificar proactivamente el nivel de riesgo en la infraestructura.

---

## 🚀 Funcionalidades Clave del Dashboard

El panel de control interactivo traduce la complejidad del grafo semántico en una interfaz táctica y visual dividida en módulos:

### ☠️ 1. Auditoría de Actores de Amenazas (Threat Actors)
* Visualización de grupos de APTs y los recursos que emplean de forma directa e indirecta.
* **Inferencia de propiedades:** Clasificación automatizada de perfiles mediante la etiqueta de alta criticidad (`High_Risk_Threat_Actor`) si emplean técnicas que apunten a brechas severas.
* Filtro inteligente dinámico por nombre o alias.

### ☣️ 2. Catálogo de Cargas Ofensivas (Malware) & Inventario Software
* Mapeo de cepas de malware activo frente a las técnicas MITRE correlacionadas por el razonador.
* **Generador de Grafos Semánticos:** Trazabilidad instantánea en formato de árbol que dibuja en pantalla el proceso del dato: *Clase base ➔ Individuo mapeado ➔ Técnicas inferidas ➔ CVEs objetivo*.

### 🎯 3. Patrones de Ataque y Técnicas Asociadas (CAPEC / MITRE)
* Inspección profunda de las tácticas operativas que implementa cada patrón, listando las debilidades objetivo del sistema de información.

### 🛡️ 4. Matriz de Mitigaciones & Planes de Acción (COA)
* Paginación interactiva y filtros por criticidad (CVSS $\ge$ 9.0 *Critical*, High, Medium).
* Mapeo de planes de contingencia (*Course of Action*) asociados dinámicamente a la causa raíz de la vulnerabilidad (CWE).

### 📈 5. Análisis de Razonamiento y Riesgo (Ontology Insights)
Una sección analítica distribuye en *4 columnas paralelas e independientes con scroll interno* los hallazgos críticos del razonador:
1.  **Actores Críticos Detectados:** Grupos aislados por inferencia lógica.
2.  **Técnicas de Alto Impacto:** Procedimientos críticos ejecutados en el sistema.
3.  **Brechas Solucionadas:** Vulnerabilidades con planes de mitigación funcionales.
4.  **🚨 Exposición (No Mitigadas):** Alerta temprana en color carmesí que aísla de forma automatizada las CVEs críticas que carecen de un *Course of Action* o mitigación, asociado en la ontología, reflejando el verdadero riesgo residual.

---

## 🧠 Tecnologías y Herramientas Utilizadas

### 🔗 Ingeniería de Conocimiento & Web Semántica
* <img src="https://img.shields.io/badge/OWL-W3C-blue?style=flat&logo=w3c" alt="OWL"> **OWL DL:** Modelado de restricciones, jerarquías de propiedades y axiomas lógicos.
* <img src="https://img.shields.io/badge/RDF-Turtle-orange?style=flat" alt="RDF"> **RDF / Turtle:** Estructuración y serialización del conocimiento de ciberseguridad.
* **Pellet:** Razonador lógico para la validación de consistencia y ejecución de reglas SWRL.

### 🛠️ Automatización y Backend Extractor
* <img src="https://img.shields.io/badge/Python-3.x-3776AB?style=flat&logo=python&logoColor=white" alt="Python"> **Python:** Motor central de ejecución del flujo de trabajo.
* **RDFLib:** Librería nativa para el procesamiento, navegación y querying programático de grafos semánticos directamente sobre el archivo local `.ttl`.
* **JSON Serialization:** Transformación síncrona de las inferencias en estructuras jerárquicas optimizadas para el rendimiento en cliente.

### 💻 Interfaz Web y Despliegue
* <img src="https://img.shields.io/badge/HTML5-E34F26?style=flat&logo=html5&logoColor=white" alt="HTML5"> **HTML5 Semántico:** Estructura modular del panel y rejillas de métricas.
* <img src="https://img.shields.io/badge/CSS3-Cyberpunk_Theme-1572B6?style=flat&logo=css3&logoColor=white" alt="CSS3"> **CSS3 Custom (Cyber-Grid UI):** Diseño oscuro basado en terminal de ciberinteligencia, grillas adaptativas fluidas y layouts unificados de scroll simétrico.
* <img src="https://img.shields.io/badge/JavaScript-ES6-F7DF1E?style=flat&logo=javascript&logoColor=black" alt="JS"> **JavaScript Vanila:** Gestión del estado de la paginación global, inyección asíncrona de datos, modales interactivos y renderizado dinámico del DOM.
* <img src="https://img.shields.io/badge/GitHub_Pages-Deployment-222222?style=flat&logo=github" alt="GitHub Pages"> **GitHub Pages:** Alojamiento y despliegue continuo de la aplicación web en entorno público de producción.

---

## 🧪 Validación y Pruebas del Grafo

La madurez del sistema semántico se ha constatado bajo tres pilares de evaluación:
1.  **Consistencia Lógica:** Verificación semántica sin contradicciones lógicas utilizando el razonador en Protégé.
2.  **Validación de Inferencias Cruzadas:** Comprobación de que las reglas de impacto propagan la criticidad de manera correcta desde una vulnerabilidad aislada hasta la ficha del *Threat Actor*.
3.  **Rendimiento y Paginación Sincrónica:** Pruebas de estrés de renderizado controlando la segmentación de tablas en bloques de 5 y 10 registros para garantizar la fluidez visual de la interfaz.

---

## 🎓 Contexto Académico

Este proyecto concluye el plan de estudios del **Grado en Ingeniería Informática**, demostrando la viabilidad de fusionar las tecnologías de la Web Semántica con la analítica defensiva en ciberseguridad.

### 🚀 Líneas de Ampliación Futura:
**Ampliación del modelo ontológico con nuevas fuentes de ciberinteligencia**
Integrar datsets adicionales que permitan incorporar nuevos tipos de amenazas, malware y vectores de ataque, así como ampliar las capacidades de correlación semántica entre vulnerabilidades, actores y campañas maliciosas.
**Extensión de clases y relaciones para mejorar el razonamiento automático**
Incorporacion de nuevas clases, permitiendo generar inferencias más complejas sobre propagación de amenazas, impacto organizacional y priorización de riesgo.
**Implementación de analisis predictivo y visualización avanzada de amenazas**
Desarrollar módulos de análisis semántico capaces de detectar patrones recurrentes de ataque y representar gráficamente cadenas de explotación.

---

## 👤 Autor

* **Francisca González Provencio**
* *Grado en Ingeniería Informática*
* **Universitat Oberta de Catalunya (UOC)**
* Área: *Web Semántica*
