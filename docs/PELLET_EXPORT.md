# 📤 Guía: Protégé + Pellet → JSON → Dashboard

## 🎯 Objetivo

Exportar resultados de ontología razonada con Pellet, convertir a JSON y desplegar en web.

---

## 📋 Paso 1: Preparar Protégé

### 1.1 Abrir Ontología
```
File → Open → tfgontologiaciberseguridad.ttl
```

### 1.2 Activar Pellet
```
Reasoner → Select Reasoner... → Pellet
Reasoner → Start Reasoner
```
Esperar ✓

### 1.3 Verificar Inferencias
- Ver subclases nuevas (CriticalVulnerability, HighRiskThreatActor)
- Comprobar relaciones inferidas en Object Properties

---

## 💾 Paso 2: Exportar

```
File → Export ontology as...
Formato: Turtle (*.ttl)
Nombre: tfgontologiaciberseguridad-reasoned.ttl
```

---

## 🐍 Paso 3: Convertir a JSON

### Instalar dependencia
```bash
pip install rdflib
```

### Script de conversión (save as `convert_ontology.py`)

```python
#!/usr/bin/env python3
import json
import sys
from rdflib import Graph, Namespace, RDF, RDFS

ONTOLOGY_NS = Namespace('http://ciberseguridad.example.org/ontology#')

def load_ontology(filepath):
    g = Graph()
    g.parse(filepath, format='turtle')
    return g

def extract_actors(g):
    actors = []
    for actor in g.subjects(RDF.type, ONTOLOGY_NS.ThreatActor):
        name = str(g.value(actor, RDFS.label, default=actor.split('#')[-1]))
        motivation = str(g.value(actor, ONTOLOGY_NS.hasMotivation, default='No especificada'))
        is_high_risk = (actor, RDF.type, ONTOLOGY_NS.HighRiskThreatActor) in g
        
        softwares = [str(s.split('#')[-1]) for s in g.objects(actor, ONTOLOGY_NS.usesSoftware)]
        techniques = [f'T{t}' for t in [str(t).split('T')[-1] for t in g.objects(actor, ONTOLOGY_NS.actorusestechnique)]]
        cves = [str(c.split('#')[-1]) for c in g.objects(actor, ONTOLOGY_NS.actorcanexploit)]
        
        actors.append({
            'id': str(actor.split('#')[-1]),
            'name': name,
            'motivation': motivation,
            'isHighRisk': is_high_risk,
            'softwares': softwares,
            'techniques': techniques,
            'cves': cves
        })
    return actors

def extract_vulnerabilities(g):
    vulns = []
    for vuln in g.subjects(RDF.type, ONTOLOGY_NS.Vulnerability):
        cve = str(g.value(vuln, ONTOLOGY_NS.hasCVEID, default=vuln.split('#')[-1]))
        cvss = float(g.value(vuln, ONTOLOGY_NS.hasCVSSScore, default=0))
        desc = str(g.value(vuln, ONTOLOGY_NS.hasDescription, default=''))
        
        vuln_type = 'Medium_Risk_Vulnerability'
        if cvss > 9.0:
            vuln_type = 'Critical_Vulnerability'
        elif 7.0 <= cvss <= 9.0:
            vuln_type = 'High_Risk_Vulnerability'
        
        cwe_obj = g.value(vuln, ONTOLOGY_NS.vulnerabilityclassifiedbyweakness)
        cwe = str(g.value(cwe_obj, RDFS.label, default='CWE-Unknown')) if cwe_obj else 'CWE-Unknown'
        mitigated = (vuln, RDF.type, ONTOLOGY_NS.MitigatedVulnerability) in g
        
        vulns.append({
            'cve': cve,
            'desc': desc,
            'severity': cvss,
            'type': vuln_type,
            'cwe': cwe,
            'mitigated': mitigated,
            'affectedSoftware': [str(s.split('#')[-1]) for s in g.objects(vuln, ONTOLOGY_NS.vulnerabilityaffectssoftware)]
        })
    return vulns

def extract_malware(g):
    malware_list = []
    for malware in g.subjects(RDF.type, ONTOLOGY_NS.Malware):
        name = str(g.value(malware, RDFS.label, default=malware.split('#')[-1]))
        
        malware_type = 'Malware'
        if (malware, RDF.type, ONTOLOGY_NS.Ransomware) in g:
            malware_type = 'Ransomware'
        elif (malware, RDF.type, ONTOLOGY_NS.TrojanHorse) in g:
            malware_type = 'Trojan Horse'
        
        techniques = [f'T{t}' for t in [str(t).split('T')[-1] for t in g.objects(malware, ONTOLOGY_NS.malwareusestechnique)]]
        cves = [str(c.split('#')[-1]) for c in g.objects(malware, ONTOLOGY_NS.malwareexploitvulnerability)]
        
        malware_list.append({
            'name': name,
            'type': malware_type,
            'techniques': ', '.join(techniques),
            'cves': ', '.join(cves),
            'trace': f'{name} ➔ malware_exploits_vulnerability (Property Chain)'
        })
    return malware_list

def extract_software(g):
    software_list = []
    for software in g.subjects(RDF.type, ONTOLOGY_NS.Software):
        name = str(g.value(software, RDFS.label, default=software.split('#')[-1]))
        actors = [str(a.split('#')[-1]) for a in g.objects(software, ONTOLOGY_NS.softwareisusedbyactor)]
        techniques = [f'T{t}' for t in [str(t).split('T')[-1] for t in g.objects(software, ONTOLOGY_NS.softwareusestechnique)]]
        vulns = [str(v.split('#')[-1]) for v in g.objects(software, ONTOLOGY_NS.softwarecompromisesvulnerability)]
        
        software_list.append({
            'name': name,
            'actor': ', '.join(actors),
            'techniques': ', '.join(techniques),
            'cves': ', '.join(vulns),
            'trace': f'{name} ➔ software_compromises_vulnerability'
        })
    return software_list

def main():
    if len(sys.argv) < 2:
        print('Uso: python convert_ontology.py <archivo_turtle>')
        sys.exit(1)
    
    filepath = sys.argv[1]
    print(f'📖 Cargando {filepath}...')
    
    g = load_ontology(filepath)
    print(f'✓ {len(g)} triples')
    
    data = {
        'metadata': {'version': '2.0.26', 'reasoner': 'Pellet'},
        'actors': extract_actors(g),
        'vulnerabilities': extract_vulnerabilities(g),
        'malware': extract_malware(g),
        'software': extract_software(g)
    }
    
    print(f'Actores: {len(data["actors"])}')
    print(f'Vulnerabilidades: {len(data["vulnerabilities"])}')
    print(f'Malware: {len(data["malware"])}')
    print(f'Software: {len(data["software"])}')
    
    with open('data/ontology-data.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    print('✅ Guardado en data/ontology-data.json')

if __name__ == '__main__':
    main()
```

### Ejecutar
```bash
python convert_ontology.py tfgontologiaciberseguridad-reasoned.ttl
```

---

## 🚀 Paso 4: Actualizar GitHub

```bash
git add data/ontology-data.json
git commit -m "Actualizar datos ontología: $(date +%Y-%m-%d)"
git push origin main
```

Dashboard se actualiza automáticamente en 2-3 minutos.

---

## ✅ Checklist

- [ ] Ontología abierta en Protégé
- [ ] Pellet ejecutándose
- [ ] Exportada como Turtle
- [ ] Script Python ejecutado
- [ ] JSON creado en data/
- [ ] Cambios pusheados
- [ ] Dashboard funciona

---

**Versión**: 2.0.26
