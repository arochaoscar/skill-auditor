# skill-auditor

Auditor de seguridad para **Claude Skills** y **MCP servers**. Audita el árbol completo del skill —no solo el `SKILL.md`, también scripts auxiliares, helpers y assets— y entrega un veredicto con evidencia específica y recomendaciones accionables por hallazgo: análisis estático de patrones peligrosos por tipo de archivo, verificación de integridad contra la fuente original, **verificación de autoría y reputación del publicador** (allowlist de vendors conocidos + detección de typosquatting), detección de drift contra auditorías previas, consulta a bases públicas de vulnerabilidades y evaluación de coherencia entre propósito declarado y acciones reales.

Incluye **modo descubrimiento**: escanea automáticamente todos los skills instalados en `~/.claude/skills/` y `.claude/skills/` del proyecto, y genera un dashboard comparativo con veredicto por skill.

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

1. **Identificación e inventario** — Determina si la entrada es un archivo, directorio, URL o modo descubrimiento. Inventaría recursivamente todos los archivos del skill con `Glob` y los clasifica por lenguaje (`.md`, `.sh`, `.py`, `.js/.ts`, configs). Los binarios embebidos se marcan como anómalos.
2. **Análisis estático multi-lenguaje** — Busca patrones determinísticos **en todos los archivos del árbol**, con reglas específicas por tipo: pipe-to-shell en `.sh`, `eval`/`exec`/`pickle.loads` en `.py`, `new Function`/`child_process` en `.js`, credenciales y exfiltración en cualquier texto. Cada hallazgo incluye archivo:línea, impacto concreto y **recomendación accionable**.
3. **Detección de drift** — Compara los hashes SHA-256 actuales contra el registro de auditorías previo. Detecta archivos modificados, nuevos o eliminados después de la última revisión.
4. **Verificación de integridad** — Compara cada archivo contra su versión canónica en GitHub raw. Reporta diferencias clasificadas por severidad.
5. **Verificación de autoría y reputación** — Consulta la GitHub API para extraer señales objetivas del owner (tipo de cuenta, antigüedad, followers, repos públicos, badge de organización verificada). Compara contra una allowlist curada de vendors confiables (Anthropic, Vercel, Microsoft, GitHub, etc.) y detecta typosquatting (distancia de Levenshtein ≤ 2). Calcula un score que se traduce en un tier: 🟢 ALTA, 🟡 MODERADA, ⚪ DESCONOCIDO o 🔴 SOSPECHOSO. El tier **modifica el umbral del veredicto**, pero nunca anula un hallazgo crítico.
6. **Consulta de CVEs** — Busca vulnerabilidades en **GitHub Advisory DB**, **OSV.dev** y **Snyk**. Únicas fuentes aceptadas; foros y redes sociales no cuentan.
7. **Análisis de coherencia** — Extrae las acciones reales del árbol completo (herramientas, rutas, dominios, dependencias) y las contrasta con el propósito declarado. Un skill que dice "ordenar notas" pero accede a `~/.ssh/` es incoherente.
8. **Reporte y dashboard** — Para un skill individual: reporte con hallazgos, inventario de red, autoría/reputación, coherencia y **recomendaciones priorizadas**. En modo descubrimiento: dashboard comparativo con tabla de veredictos por skill y acciones globales en orden de prioridad.

### Allowlist personalizada

Puedes mantener tu propia lista de vendors confiables en `~/.claude/skill-auditor-allowlist.txt` (un owner de GitHub por línea). El skill la fusiona con la allowlist curada en tiempo de auditoría.

Veredictos posibles:

- ✅ **APTO** — sin hallazgos críticos ni altos, integridad verificada, sin drift ni CVEs.
- ⚠️ **PRECAUCIÓN** — hallazgos altos, integridad no verificable, drift no justificado, o coherencia cuestionable.
- 🚫 **NO INSTALAR** — cualquier hallazgo crítico, integridad comprometida o CVE sin parchear.

El skill mantiene un registro mínimo en `~/.claude/skill-audits.json` con solo metadatos (nombre, hashes por archivo, fecha, veredicto, archivos auditados), nunca el contenido de los archivos. Este registro alimenta la detección de drift en auditorías posteriores.

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
