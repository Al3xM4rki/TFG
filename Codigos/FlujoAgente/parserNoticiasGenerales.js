const allowed = {
  category: ["security_news", "technology_news", "vendor_update", "other", "cve"],
  status: ["not_affected", "possibly_affected", "confirmed_affected", "unknown"],
  alert_level: ["none", "low", "medium", "high", "critical"],
  match_type: ["product", "vendor", "keyword", "version", "dependency", "ecosystem", "cpe"],
  impact: ["none", "low", "medium", "high", "critical"],
  source_type: ["news", "vendor_advisory", "other", "nvd", "cisa"],
  source_confidence: ["low", "medium", "high"]
};

function extractAnalysisJsonObject(text) {
  if (!text || typeof text !== "string") return null;

  const cleaned = text
    .replace(/```json/gi, "")
    .replace(/```/g, "")
    .trim();

  const candidates = [];

  for (let start = 0; start < cleaned.length; start++) {
    if (cleaned[start] !== "{") continue;

    let depth = 0;
    let inString = false;
    let escape = false;

    for (let i = start; i < cleaned.length; i++) {
      const char = cleaned[i];

      if (escape) {
        escape = false;
        continue;
      }

      if (char === "\\") {
        escape = true;
        continue;
      }

      if (char === "\"") {
        inString = !inString;
        continue;
      }

      if (inString) continue;

      if (char === "{") depth++;
      if (char === "}") depth--;

      if (depth === 0) {
        const candidateText = cleaned.slice(start, i + 1);

        try {
          const parsed = JSON.parse(candidateText);

          if (
            parsed &&
            typeof parsed === "object" &&
            !Array.isArray(parsed)
          ) {
            candidates.push(parsed);
          }
        } catch (error) {}

        break;
      }
    }
  }

  const validAnalysisObjects = candidates.filter(obj =>
    Object.prototype.hasOwnProperty.call(obj, "id") &&
    Object.prototype.hasOwnProperty.call(obj, "relevant") &&
    Object.prototype.hasOwnProperty.call(obj, "category") &&
    Object.prototype.hasOwnProperty.call(obj, "status") &&
    Object.prototype.hasOwnProperty.call(obj, "alert_level") &&
    Object.prototype.hasOwnProperty.call(obj, "confidence") &&
    Object.prototype.hasOwnProperty.call(obj, "cve_ids") &&
    Object.prototype.hasOwnProperty.call(obj, "affected_stack_items")
  );

  if (validAnalysisObjects.length > 0) {
    return validAnalysisObjects[validAnalysisObjects.length - 1];
  }

  return null;
}

function asArray(value) {
  return Array.isArray(value) ? value : [];
}

function normalizeEnum(value, validValues, fallback) {
  return validValues.includes(value) ? value : fallback;
}

function normalizeConfidence(value, fallback = 0.5) {
  const number = Number(value);

  if (!Number.isFinite(number)) return fallback;
  if (number < 0) return 0;
  if (number >= 1) return 0.95;

  return Math.round(number * 100) / 100;
}

function normalizeCves(value) {
  return asArray(value)
    .filter(v => typeof v === "string")
    .map(v => v.trim().toUpperCase())
    .filter(v => /^CVE-\d{4}-\d{4,7}$/.test(v));
}

function normalizeSources(value) {
  return asArray(value)
    .map(source => ({
      type: normalizeEnum(source?.type, allowed.source_type, "other"),
      url: typeof source?.url === "string" ? source.url.trim() : "",
      confidence: normalizeEnum(source?.confidence, allowed.source_confidence, "medium")
    }))
    .filter(source => source.url);
}

function normalizeAffectedStackItems(value) {
  return asArray(value).map(item => ({
    name: item?.name || "",
    vendor: item?.vendor || "",
    installed_versions: asArray(item?.installed_versions),
    matched_version: item?.matched_version ?? null,
    affected_versions: item?.affected_versions || "",
    match_type: normalizeEnum(item?.match_type, allowed.match_type, "keyword"),
    evidence: item?.evidence || "",
    impact: normalizeEnum(item?.impact, allowed.impact, "none")
  }));
}

function fallbackResult(row, message) {
  return {
    id: null,
    relevant: false,
    category: "security_news",
    status: "unknown",
    alert_level: "none",
    confidence: 0.3,
    cve_ids: [],
    affected_stack_items: [],
    reasoning_summary: `Parser could not extract a valid non-CVE analysis JSON object from the model output. ${message || ""}`.trim(),
    recommended_action: "Review the model output manually.",
    sources: [],
    requires_human_review: true,

    should_send_alert: false,
    procesado: "SI",
    severidad: "none",
    relevante: false,
    requiere_revision: true,

    resultado_agente: null,
    parser_error: true,
    raw_agent_output: row.output || null
  };
}

return $input.all().map(item => {
  const row = item.json;

  const agentText =
    typeof row.output === "string"
      ? row.output
      : JSON.stringify(row);

  const parsed = extractAnalysisJsonObject(agentText);

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return {
      json: fallbackResult(row, "No valid analysis JSON object found.")
    };
  }

  const cveIds = normalizeCves(parsed.cve_ids);

  const category = normalizeEnum(
    parsed.category,
    allowed.category,
    "security_news"
  );

  const status = normalizeEnum(parsed.status, allowed.status, "unknown");

  let alertLevel = normalizeEnum(parsed.alert_level, allowed.alert_level, "none");

  let affectedStackItems = normalizeAffectedStackItems(parsed.affected_stack_items);

  let relevant = Boolean(parsed.relevant);

  if (status === "not_affected") {
    relevant = false;
    alertLevel = "none";
    affectedStackItems = [];
  }

  if (status === "possibly_affected" || status === "confirmed_affected") {
    relevant = true;
  }

  const confidence = normalizeConfidence(
    parsed.confidence,
    status === "not_affected" ? 0.85 : 0.5
  );

  const sources = normalizeSources(parsed.sources);

  const requiresHumanReview =
    Boolean(parsed.requires_human_review) ||
    status === "unknown";

  const shouldSendAlert =
    relevant === true &&
    status !== "not_affected" &&
    alertLevel !== "none";

  const result = {
    id: parsed.id ?? null,
    relevant,
    category,
    status,
    alert_level: alertLevel,
    confidence,
    cve_ids: cveIds,
    affected_stack_items: affectedStackItems,
    reasoning_summary: parsed.reasoning_summary || "",
    recommended_action: parsed.recommended_action || "",
    sources,
    requires_human_review: requiresHumanReview,

    should_send_alert: shouldSendAlert,
    procesado: "SI",
    severidad: alertLevel,
    relevante: relevant,
    requiere_revision: requiresHumanReview,

    resultado_agente: {
      ...parsed,
      relevant,
      category,
      status,
      alert_level: alertLevel,
      confidence,
      cve_ids: cveIds,
      affected_stack_items: affectedStackItems,
      sources,
      requires_human_review: requiresHumanReview,
      should_send_alert: shouldSendAlert
    },

    parser_error: false,
    raw_agent_output: agentText
  };

  return {
    json: result
  };
});