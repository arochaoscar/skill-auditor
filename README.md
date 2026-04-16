# skill-auditor

Auditor de seguridad para **Claude Skills** y **MCP servers**. Audita el árbol completo del skill —no solo el `SKILL.md`, también scripts auxiliares, helpers y assets— y entrega un veredicto con evidencia específica y recomendaciones accionables por hallazgo: análisis estático de patrones peligrosos por tipo de archivo, verificación de integridad contra la fuente original, detección de drift contra auditorías previas, consulta a bases públicas de vulnerabilidades y evaluación de coherencia entre propósito declarado y acciones reales.

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
5. **Consulta de CVEs** — Busca vulnerabilidades en **GitHub Advisory DB**, **OSV.dev** y **Snyk**. Únicas fuentes aceptadas; foros y redes sociales no cuentan.
6. **Análisis de coherencia** — Extrae las acciones reales del árbol completo (herramientas, rutas, dominios, dependencias) y las contrasta con el propósito declarado. Un skill que dice "ordenar notas" pero accede a `~/.ssh/` es incoherente.
7. **Reporte y dashboard** — Para un skill individual: reporte con hallazgos, inventario de red, coherencia y **recomendaciones priorizadas**. En modo descubrimiento: dashboard comparativo con tabla de veredictos por skill y acciones globales en orden de prioridad.

Veredictos posibles:

- ✅ **APTO** — sin hallazgos críticos ni altos, integridad verificada, sin drift ni CVEs.
- ⚠️ **PRECAUCIÓN** — hallazgos altos, integridad no verificable, drift no justificado, o coherencia cuestionable.
- 🚫 **NO INSTALAR** — cualquier hallazgo crítico, integridad comprometida o CVE sin parchear.

El skill mantiene un registro mínimo en `~/.claude/skill-audits.json` con solo metadatos (nombre, hashes por archivo, fecha, veredicto, archivos auditados), nunca el contenido de los archivos. Este registro alimenta la detección de drift en auditorías posteriores.

## Instalación

Este skill está diseñado para Claude Code. Puedes instalarlo de forma **global** (disponible en todas tus sesiones) o **por proyecto**.

### Instalación global

```bash
mkdir -p ~/.claude/skills/skill-auditor
curl -fsSL https://raw.githubusercontent.com/arochaoscar/skill-auditor/main/SKILL.md \
  -o ~/.claude/skills/skill-auditor/SKILL.md
```

### Instalación por proyecto

Desde la raíz del proyecto:

```bash
mkdir -p .claude/skills/skill-auditor
curl -fsSL https://raw.githubusercontent.com/arochaoscar/skill-auditor/main/SKILL.md \
  -o .claude/skills/skill-auditor/SKILL.md
```

### Instalación por git clone

```bash
git clone https://github.com/arochaoscar/skill-auditor.git ~/.claude/skills/skill-auditor
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
- **Este skill también es un archivo de texto**: aplícale el mismo escepticismo que a cualquier otro. Verifica su integridad desde esta fuente antes de instalarlo.

Este reporte no reemplaza una auditoría de código profesional.

## Licencia

MIT
