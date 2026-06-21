const items = $input.all();
const output = [];

for (const item of items) {
  const row = item.json;

  const text = [
    row.titulo,
    row.mensaje_bruto,
    row.url
  ].filter(Boolean).join("\n");

  const matches = text.match(/CVE-\d{4}-\d{4,7}/gi) || [];
  const cves = [...new Set(matches.map(cve => cve.toUpperCase()))].sort();

  if (cves.length === 0) {
    output.push({
      json: {
        ...row,
        cves_detectados: [],
        hay_cve: false,
        cve_detectado: null,
        merge_key: null
      }
    });

    continue;
  }

  for (const cve of cves) {
    output.push({
      json: {
        ...row,
        cves_detectados: cves,
        hay_cve: true,
        cve_detectado: cve,
        merge_key: cve
      }
    });
  }
}

return output;