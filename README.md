# TFG--Ciberseguridad
# 🛡️ Web Semántica para el Análisis de Vulnerabilidades en Ciberseguridad

Este proyecto forma parte del **Trabajo Fin de Grado (TFG)** en Ingeniería Informática y tiene como objetivo el **diseño e implementación de una ontología de ciberseguridad**, junto con una **aplicación web semántica** que permita consultar y relacionar información sobre vulnerabilidades de forma estructurada y automática.

La solución se basa en tecnologías de la **Web Semántica** y utiliza datos procedentes de fuentes oficiales y ampliamente reconocidas en el ámbito de la ciberseguridad, como **NVD** y **MITRE ATT&CK**.

---

## 🌐 Descripción general

La creciente cantidad de información sobre vulnerabilidades, ataques y técnicas de explotación hace necesario disponer de mecanismos que permitan **organizar, integrar y consultar este conocimiento de forma eficiente**.

Este proyecto propone:
- Una **ontología OWL** que modela vulnerabilidades, técnicas de ataque, mitigaciones y activos afectados.
- Una **web semántica** que permite realizar consultas SPARQL de forma visual e intuitiva.
- Datos RDF (TTL), transformados desde NVD y MITRE ATT&CK, para poblar la ontologia de datos reales.
- Un enfoque orientado al **análisis preventivo de amenazas** y a la reutilización del conocimiento.

---

## 🚀 Funcionalidades clave

La aplicación web permite realizar las siguientes consultas semánticas:

### 🔴 1. Riesgos críticos
- Identificación de vulnerabilidades con **CVSS mayor de 9.5**
- Ordenación de riesgos en función de su criticidad

### 🎯 2. Tácticas y técnicas de ataque
- Consulta de tácticas y técnicas basadas en **MITRE ATT&CK**
- Relación entre técnicas y su táctica asociada

### 🛠️ 3. Mitigaciones
- Listado de mitigaciones asociadas a vulnerabilidades

### 🔍 4. Búsqueda por CVE
- Consulta detallada de una vulnerabilidad concreta mediante su **CVE**, introduciendo el valor CVE-ID
- Información mostrada:
  - Descripción
  - CVSS

Todos los resultados se presentan en un **panel unificado**, facilitando la navegación y el análisis.

---

## 🧠 Tecnologías utilizadas

### 🔗 Web Semántica
- **OWL** – Modelado de la ontología
- **RDF** – Representación de datos
- **SPARQL** – Lenguaje de consultas semánticas

### 🧩 Herramientas
- **Protégé** – Diseño y validación de la ontología
- **GraphDB** – Almacenamiento RDF (entorno de desarrollo)
- **GitHub Pages** – Despliegue del frontend

### 💻 Desarrollo Web
- **HTML5**
- **CSS3**
- **JavaScript (Vanilla JS)**

---

## 🧪 Validación y pruebas

El correcto funcionamiento de la ontología y de la web semántica se valida mediante:
- Consultas SPARQL diseñadas para responder a **preguntas reales del dominio**
- Pruebas funcionales de cada una de las funcionalidades implementadas
- Comprobación de consistencia y reutilización del conocimiento

---

## 🎓 Contexto académico

Este proyecto ha sido desarrollado como **Trabajo Fin de Grado**, con un enfoque formativo y profesional, orientado al ámbito de la **ciberseguridad** y la **web semántica**.

El trabajo sienta las bases para futuras ampliaciones, como:
- Integración de nuevas fuentes de datos
- Razonamiento automático
- Herramientas avanzadas de inteligencia en ciberseguridad

---

## 👤 Autor

**[Francisca González Provencio]**  
Grado en Ingeniería Informática. UOC 
TFG – Web Semántica y Ciberseguridad
