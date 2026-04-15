# skill-auditor

Auditor de seguridad para **Claude Skills** y **MCP servers**. Analiza archivos `SKILL.md` antes (o después) de instalarlos y entrega un veredicto claro con evidencia específica: análisis estático de patrones peligrosos, verificación de integridad contra la fuente original, consulta a bases de datos públicas de vulnerabilidades y evaluación de coherencia entre el propósito declarado y las acciones reales del skill.

## ¿Por qué existe este skill?

Los skills y los MCP servers son archivos de texto que instruyen a Claude sobre cómo comportarse y qué herramientas usar. Instalar un skill sin revisarlo es equivalente a ejecutar un script de un desconocido: puede leer archivos sensibles, contactar servidores externos o modificar tu entorno. Este skill aplica una revisión estructurada y reproducible antes de que eso ocurra.

## ¿Cuándo se activa?

El skill se activa automáticamente cuando dices frases como:

- "audita este skill"
- "revisa este SKILL.md"
- "¿es seguro instalar X?"
- "verifica la integridad de ..."
- "analiza este MCP"

También se activa cuando compartes una URL de GitHub que apunta a un skill o MCP server.

Acepta tres tipos de entrada:

1. URL de GitHub apuntando al skill/MCP
2. Ruta local a un `SKILL.md` ya instalado
3. Nombre de un paquete npm o skill conocido

## Cómo funciona

El skill ejecuta seis pasos en orden:

1. **Identificación** — Confirma qué archivo va a analizar y de dónde proviene.
2. **Análisis estático** — Busca patrones determinísticos en tres niveles de severidad (crítico/alto/medio): acceso a credenciales, exfiltración, modificación del entorno, evasión de sandbox, obfuscación, etc. Cada hallazgo se reporta con línea exacta.
3. **Verificación de integridad** — Compara el archivo contra la versión original en su fuente canónica (GitHub raw). Detecta modificaciones respecto al upstream.
4. **Consulta a bases de vulnerabilidades** — Busca CVEs en **GitHub Advisory DB**, **OSV.dev** y **Snyk**. Estas son las únicas fuentes aceptadas; foros y redes sociales no cuentan como threat intelligence.
5. **Análisis de coherencia** — Evalúa si cada acción del skill es consistente con su propósito declarado. Un skill que dice "ordenar notas" pero accede a `~/.ssh/` es incoherente.
6. **Veredicto** — Reporte consolidado con uno de tres resultados:
   - ✅ **APTO** — sin hallazgos críticos ni altos, integridad verificada, sin CVEs.
   - ⚠️ **PRECAUCIÓN** — hallazgos altos, integridad no verificable, o coherencia cuestionable.
   - 🚫 **NO INSTALAR** — cualquier hallazgo crítico, integridad comprometida o CVE sin parchear.

El skill mantiene un registro mínimo de auditorías en `.claude/skill-audits.json` con solo metadatos (nombre, hash SHA-256, fecha, veredicto), nunca el contenido del archivo analizado.

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
