const items = $input.all();

const severityRank = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4
};

const statusRank = {
  not_affected: 0,
  unknown: 1,
  possibly_affected: 2,
  confirmed_affected: 3
};

function unique(array) {
  return [...new Set(array.filter(Boolean))];
}

function pickHighestSeverity(values) {
  return values.reduce((best, current) => {
    const bestRank = severityRank[best] ?? 0;
    const currentRank = severityRank[current] ?? 0;
    return currentRank > bestRank ? current : best;
  }, "none");
}

function pickHighestStatus(values) {
  return values.reduce((best, current) => {
    const bestRank = statusRank[best] ?? 0;
    const currentRank = statusRank[current] ?? 0;
    return currentRank > bestRank ? current : best;
  }, "not_affected");
}

function toPostgresArray(values) {
  const cleaned = unique(values);

  if (cleaned.length === 0) return null;

  return `{${cleaned.join(",")}}`;
}

const grouped = new Map();

for (const item of items) {
  const row = item.json;
  const id = row.id;

  if (id === null || id === undefined) {
    continue;
  }

  if (!grouped.has(id)) {
    grouped.set(id, {
      id,
      relevant: false,
      status_values: [],
      severity_values: [],
      confidence_values: [],
      cve_ids: [],
      affected_stack_items: [],
      sources: [],
      resultados_cves: [],
      requires_human_review: false,
      parser_error: false,
      should_send_alert: false
    });
  }

  const group = grouped.get(id);

  const currentCves = Array.isArray(row.cve_ids) ? row.cve_ids : [];

  group.relevant = group.relevant || row.relevant === true;
  group.requires_human_review = group.requires_human_review || row.requires_human_review === true;
  group.parser_error = group.parser_error || row.parser_error === true;
  group.should_send_alert = group.should_send_alert || row.should_send_alert === true;

  group.status_values.push(row.status || "unknown");
  group.severity_values.push(row.severidad || row.alert_level || "none");

  if (typeof row.confidence === "number") {
    group.confidence_values.push(row.confidence);
  }

  group.cve_ids.push(...currentCves);

  if (Array.isArray(row.affected_stack_items)) {
    group.affected_stack_items.push(...row.affected_stack_items);
  }

  if (Array.isArray(row.sources)) {
    group.sources.push(...row.sources);
  }

  group.resultados_cves.push({
    cve_ids: currentCves,
    status: row.status || "unknown",
    alert_level: row.alert_level || "none",
    severity: row.severidad || row.alert_level || "none",
    relevant: row.relevant === true,
    confidence: row.confidence ?? null,
    should_send_alert: row.should_send_alert === true,
    requires_human_review: row.requires_human_review === true,
    reasoning_summary: row.reasoning_summary || "",
    recommended_action: row.recommended_action || "",
    affected_stack_items: row.affected_stack_items || [],
    sources: row.sources || [],
    parser_error: row.parser_error === true,
    resultado_agente: row.resultado_agente || null
  });
}

const output = [];

for (const group of grouped.values()) {
  const cveIds = unique(group.cve_ids);

  const finalSeverity = pickHighestSeverity(group.severity_values);
  const finalStatus = pickHighestStatus(group.status_values);

  const avgConfidence =
    group.confidence_values.length > 0
      ? Math.round(
          (group.confidence_values.reduce((a, b) => a + b, 0) / group.confidence_values.length) * 100
        ) / 100
      : 0.5;

  const uniqueSources = [];
  const seenSourceUrls = new Set();

  for (const source of group.sources) {
    if (!source?.url) continue;

    if (!seenSourceUrls.has(source.url)) {
      seenSourceUrls.add(source.url);
      uniqueSources.push(source);
    }
  }

  const affectedStackItems = [];
  const seenAffected = new Set();

  for (const affected of group.affected_stack_items) {
    const key = [
      affected?.name || "",
      affected?.vendor || "",
      affected?.match_type || "",
      affected?.matched_version || ""
    ].join("|");

    if (!seenAffected.has(key)) {
      seenAffected.add(key);
      affectedStackItems.push(affected);
    }
  }

  const shouldSendAlert =
    group.should_send_alert === true ||
    (
      group.relevant === true &&
      finalStatus !== "not_affected" &&
      finalSeverity !== "none"
    );

  output.push({
    json: {
      id: group.id,

      relevant: group.relevant,
      relevante: group.relevant,

      status: finalStatus,
      alert_level: finalSeverity,
      severidad: finalSeverity,

      confidence: avgConfidence,

      cve_ids: cveIds,
      cve_detectado: cveIds.length > 0 ? cveIds[0] : null,
      cve_detectado_pg: toPostgresArray(cveIds),

      affected_stack_items: affectedStackItems,
      sources: uniqueSources,

      requires_human_review: group.requires_human_review,
      requiere_revision: group.requires_human_review,

      should_send_alert: shouldSendAlert,

      procesado: "SI",

      parser_error: group.parser_error,

      resultados_cves: group.resultados_cves,

      resultado_agente: {
        id: group.id,
        relevant: group.relevant,
        status: finalStatus,
        alert_level: finalSeverity,
        confidence: avgConfidence,
        cve_ids: cveIds,
        affected_stack_items: affectedStackItems,
        sources: uniqueSources,
        requires_human_review: group.requires_human_review,
        should_send_alert: shouldSendAlert,
        resultados_cves: group.resultados_cves
      }
    }
  });
}

return output;