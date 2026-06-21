function extractJsonLikeField(raw, fieldName) {
  if (!raw || typeof raw !== "string") return null;

  const pattern = new RegExp(`"${fieldName}"\\s*:\\s*"([\\s\\S]*?)"\\s*,?\\s*(?="|}|\\n🔹)`, "i");
  const match = raw.match(pattern);

  if (!match) return null;

  return match[1]
    .replace(/\\"/g, '"')
    .replace(/\\n/g, "\n")
    .trim();
}

function limitArray(value, max) {
  return Array.isArray(value) ? value.slice(0, max) : [];
}

return $input.all().map(item => {
  const row = item.json;
  const rawText = String(row.mensaje_bruto || "");

  const titleFromRaw = extractJsonLikeField(rawText, "Title");
  const sourceFromRaw = extractJsonLikeField(rawText, "Source");
  const typeFromRaw = extractJsonLikeField(rawText, "Type");
  const detectionDateFromRaw = extractJsonLikeField(rawText, "Detection Date");
  const contentFromRaw = extractJsonLikeField(rawText, "Content");

  const newsText = row.texto_completo || contentFromRaw || rawText;

  const cveData = row.cve_data || {};

  return {
    json: {
      id: row.id,
      fecha: row.fecha,
      canal: row.canal,
      procesado: row.procesado || "NO",

      merge_key: row.merge_key || row.cve_detectado || cveData.id || null,
      cve_detectado: row.cve_detectado || cveData.id || null,
      cves_detectados: row.cves_detectados || [],

      news: {
        title:
          row.titulo ||
          titleFromRaw ||
          cveData.cisa?.vulnerability_name ||
          row.cve_detectado ||
          cveData.id ||
          null,

        source: sourceFromRaw || row.canal || null,
        url: row.url || null,
        type: typeFromRaw || "cve",
        detection_date: detectionDateFromRaw || row.fecha || null,
        text: newsText
      },

      cve: {
        id: cveData.id || row.cve_detectado || null,
        found_in_nvd: cveData.found_in_nvd === true,
        source: cveData.source || null,
        published: cveData.published || null,
        last_modified: cveData.last_modified || null,
        status: cveData.status || null,
        description: cveData.description || null,
        cvss: cveData.cvss || null,
        cisa: cveData.cisa || null,
        weaknesses: limitArray(cveData.weaknesses, 10),
        affected_cpes: limitArray(cveData.affected_cpes, 40),
        references: limitArray(cveData.references, 10)
      }
    }
  };
});