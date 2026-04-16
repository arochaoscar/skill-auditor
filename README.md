# skill-auditor

Auditor de seguridad para **Claude Skills** y **MCP servers**. Audita el árbol completo del skill —no solo el `SKILL.md`, también scripts, helpers y assets— y entrega un **score numérico (0-100)** con veredicto categórico, evidencia específica y recomendaciones accionables por hallazgo.

**Capacidades:**
- Análisis estático multi-lenguaje (patrones por tipo de archivo: Shell, Python, JS/TS, PowerShell/Batch)
- Verificación de integridad contra la fuente canónica
- Verificación de autoría y reputación del publicador (allowlist + anti-typosquatting)
- **Análisis de dependencias transitivas (SCA)** — detecta `package.json`, `requirements.txt`, `go.mod`, etc. y busca CVEs en cada dependencia
- Detección de drift contra auditorías previas
- Consulta a bases de vulnerabilidades (GitHub Advisory DB, OSV.dev, Snyk)
- Evaluación de coherencia entre propósito declarado y acciones reales
- **Exportación de reportes** a archivo `.md` y `.json` en `~/.claude/skill-audit-reports/`
- **Modo watch** con hooks de Claude Code para re-auditoría automática al instalar/actualizar skills
- **Modo descubrimiento**: audita todos los skills instalados y genera un dashboard comparativo con score por skill
- Cross-platform: macOS, Linux y Windows

## ¿Por qué existe este skill?

Los skills y los MCP servers son archivos de texto que instruyen a Claude sobre cómo comportarse y qué herramientas usar. Instalar un skill sin revisarlo es equivalente a ejecutar un script de un desconocido: puede leer archivos sensibles, contactar servidores externos o modificar tu entorno. Este skill aplica una revisión estructurada y reproducible antes de que eso ocurra.

## ¿Cuándo se activa?

El skill se activa automáticamente cuando dices frases como:

- "audita este skill"
- "revisa este SKILL.md"
- "¿es seguro instalar X?"
- "verifica la integridad de ..."
- "analiza este MCP"
- "audita mis skills instalados"
- "revisa todos mis skills"
- "qué skills tengo instalados"

También se activa cuando compartes una URL de GitHub que apunta a un skill/MCP o una ruta a un directorio de skill.

Acepta cuatro tipos de entrada:

1. URL de GitHub apuntando al skill/MCP (audita todo el árbol del repo)
2. Ruta local a un `SKILL.md` (detecta su directorio y audita todo el árbol)
3. Ruta local a un directorio completo
4. Nombre de un paquete npm o skill conocido
5. Ninguna entrada → modo descubrimiento: audita todos los skills instalados

## Cómo funciona

El skill ejecuta un pipeline de pasos:

1. **Detección de plataforma** — Identifica macOS, Linux o Windows y adapta rutas, comandos y patrones.
2. **Identificación e inventario** — Determina si la entrada es un archivo, directorio, URL o modo descubrimiento. Inventaría recursivamente todos los archivos del skill con `Glob` y los clasifica por lenguaje (`.md`, `.sh`, `.py`, `.js/.ts`, `.ps1/.bat`, configs). Binarios embebidos se marcan como anómalos.
3. **Análisis estático multi-lenguaje** — Patrones determinísticos en todos los archivos del árbol, con reglas específicas por tipo: pipe-to-shell en `.sh`, `eval`/`exec`/`pickle.loads` en `.py`, `new Function`/`child_process` en `.js`, download cradles/LOLBins/persistencia en `.ps1/.bat`, credenciales y exfiltración en cualquier texto. Cada hallazgo incluye archivo:línea, impacto y **recomendación accionable**.
4. **Detección de drift** — Compara SHA-256 actuales contra el registro de auditorías previo. Detecta archivos modificados, nuevos o eliminados.
5. **Verificación de integridad** — Compara cada archivo contra su versión canónica en GitHub raw. Reporta diferencias por severidad.
6. **Verificación de autoría y reputación** — Consulta GitHub API: tipo de cuenta, antigüedad, followers, badge de org verificada. Compara contra allowlist curada + detecta typosquatting (Levenshtein ≤ 2). Score → tier (🟢 ALTA / 🟡 MODERADA / ⚪ DESCONOCIDO / 🔴 SOSPECHOSO) que modifica el veredicto pero nunca anula un hallazgo crítico.
7. **Consulta de CVEs** — GitHub Advisory DB, OSV.dev y Snyk.
8. **Análisis de dependencias transitivas (SCA)** — Detecta manifiestos (`package.json`, `requirements.txt`, `go.mod`, etc.), extrae dependencias directas y transitivas (via lockfiles), y busca CVEs por ecosistema. Reporta paquetes vulnerables, deprecated y rangos sueltos sin lockfile.
9. **Análisis de coherencia** — Extrae acciones reales de todo el árbol y las contrasta con el propósito declarado.
10. **Score numérico (0-100)** — Fórmula ponderada que resta penalizaciones por hallazgo, CVE, drift e incoherencia, con bonificaciones por reputación alta e integridad verificada. Se traduce a veredicto categórico (80-100: APTO, 40-79: PRECAUCIÓN, 0-39: NO INSTALAR) pero un solo 🔴 fuerza NO INSTALAR independientemente del score.
11. **Reporte y dashboard** — Reporte individual con score, hallazgos, SCA, autoría, coherencia, comparación con auditoría previa y recomendaciones priorizadas. En modo descubrimiento: dashboard comparativo ordenado por score.
12. **Exportación** — Exporta el reporte a `~/.claude/skill-audit-reports/` como `.md` (lectura humana) y `.json` (consumo programático).

### Modo watch (re-auditoría automática)

Configura un hook de Claude Code para disparar auditorías automáticamente cuando un skill se instala o actualiza. También soporta triggers programados (cron) para auditorías periódicas de todos los skills instalados. Cuando se re-audita un skill, el reporte incluye una comparación de score y hallazgos contra la versión anterior.

### Allowlist personalizada

Mantén tu propia lista de vendors confiables en `~/.claude/skill-auditor-allowlist.txt` (un owner de GitHub por línea). El skill la fusiona con la allowlist curada en tiempo de auditoría.

### Veredictos

- ✅ **APTO** (score 80-100) — sin hallazgos críticos ni altos, integridad verificada, sin drift ni CVEs.
- ⚠️ **PRECAUCIÓN** (score 40-79) — hallazgos altos, integridad no verificable, drift no justificado, dependencias vulnerables, o coherencia cuestionable.
- 🚫 **NO INSTALAR** (score 0-39 o cualquier 🔴) — hallazgo crítico, integridad comprometida, CVE sin parchear, o autor sospechoso con hallazgos.

El skill mantiene un registro en `~/.claude/skill-audits.json` con metadatos (hashes, score, veredicto, dependencias, autor), nunca contenido de archivos. Los reportes exportados se almacenan en `~/.claude/skill-audit-reports/`.

## Compatibilidad

Funciona en **macOS**, **Linux** y **Windows**. El skill detecta el sistema operativo del host en cada ejecución y adapta:

- **Rutas**: `~/.claude/skills/` en Unix; `%USERPROFILE%\.claude\skills\` en Windows.
- **Comandos de hash**: `shasum -a 256` (macOS), `sha256sum` (Linux), `Get-FileHash` (PowerShell) o `certutil -hashfile` (cmd).
- **Comandos de descubrimiento**: `ls` en Unix, `Get-ChildItem` en PowerShell, `dir /b /ad` en cmd.
- **Patrones de análisis estático**: además de los universales, se aplican reglas específicas para Unix (`~/.ssh`, `crontab`, `.bashrc`) **y** para Windows (registro, tareas programadas, LOLBins como `certutil`/`bitsadmin`/`regsvr32`, PowerShell download cradles, ejecución codificada). Los patrones de ambas plataformas se aplican siempre, porque un script puede atacar Windows desde un skill descargado en macOS.

## Instalación

Este skill está diseñado para Claude Code. Puedes instalarlo de forma **global** (disponible en todas tus sesiones) o **por proyecto**.

### macOS / Linux

Instalación global:
```bash
mkdir -p ~/.claude/skills/skill-auditor
curl -fsSL https://raw.githubusercontent.com/arochaoscar/skill-auditor/main/SKILL.md \
  -o ~/.claude/skills/skill-auditor/SKILL.md
```

Instalación por proyecto (desde la raíz del proyecto):
```bash
mkdir -p .claude/skills/skill-auditor
curl -fsSL https://raw.githubusercontent.com/arochaoscar/skill-auditor/main/SKILL.md \
  -o .claude/skills/skill-auditor/SKILL.md
```

### Windows (PowerShell)

Instalación global:
```powershell
New-Item -ItemType Directory -Force -Path "$env:USERPROFILE\.claude\skills\skill-auditor" | Out-Null
Invoke-WebRequest `
  -Uri "https://raw.githubusercontent.com/arochaoscar/skill-auditor/main/SKILL.md" `
  -OutFile "$env:USERPROFILE\.claude\skills\skill-auditor\SKILL.md"
```

Instalación por proyecto:
```powershell
New-Item -ItemType Directory -Force -Path ".claude\skills\skill-auditor" | Out-Null
Invoke-WebRequest `
  -Uri "https://raw.githubusercontent.com/arochaoscar/skill-auditor/main/SKILL.md" `
  -OutFile ".claude\skills\skill-auditor\SKILL.md"
```

### Instalación por git clone (cualquier plataforma)

```bash
# macOS / Linux
git clone https://github.com/arochaoscar/skill-auditor.git ~/.claude/skills/skill-auditor
```

```powershell
# Windows
git clone https://github.com/arochaoscar/skill-auditor.git "$env:USERPROFILE\.claude\skills\skill-auditor"
```

### Verificación

Tras instalarlo, abre Claude Code y pide:

> audita el skill en ~/.claude/skills/skill-auditor/SKILL.md

El skill debería auditarse a sí mismo y devolver un veredicto. Si no responde, verifica que el archivo `SKILL.md` esté en la ruta correcta y que el frontmatter YAML no esté corrupto.

## Uso

Una vez instalado, invócalo de forma natural:

```
> audita este skill: https://github.com/algun-usuario/algun-skill
> revisa el SKILL.md que acabo de descargar en ~/Downloads/nuevo-skill.md
> ¿es seguro instalar el paquete @example/mcp-server?
```

El skill te devolverá un reporte estructurado con hallazgos categorizados, verificación de integridad y veredicto final.

## Limitaciones

El propio SKILL.md declara sus límites y son importantes:

- **Skills privados o sin fuente pública**: la verificación de integridad no es posible.
- **Skills muy nuevos**: probablemente no tendrán CVEs en las bases consultadas — ausencia de CVEs no implica seguridad.
- **Obfuscación avanzada**: el análisis estático puede no detectar payloads que solo se manifiestan en ejecución.
- **Reputación ≠ seguridad**: una organización reconocida puede publicar un skill comprometido (cuenta hackeada, empleado malicioso, dependency confusion). El tier de reputación es una señal contextual, no una garantía. Por eso nunca anula hallazgos críticos ni CVEs.
- **Este skill también es un archivo de texto**: aplícale el mismo escepticismo que a cualquier otro. Verifica su integridad desde esta fuente antes de instalarlo.

Este reporte no reemplaza una auditoría de código profesional.

## Licencia

MIT
