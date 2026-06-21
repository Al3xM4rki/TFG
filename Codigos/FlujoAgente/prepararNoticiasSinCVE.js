return $input.all().map(item => {
  const row = item.json;

  return {
    json: {
      id: row.id,
      fecha: row.fecha,
      canal: row.canal,
      procesado: row.procesado || "NO",

      merge_key: null,
      cve_detectado: null,
      cves_detectados: [],

      news: {
        title: row.titulo || null,
        source: row.canal || null,
        url: row.url || null,
        type: "security_news",
        detection_date: row.fecha || null,
        text: row.mensaje_bruto || ""
      },

      cve: {
        id: null,
        found_in_nvd: false,
        source: null,
        published: null,
        last_modified: null,
        status: null,
        description: null,
        cvss: null,
        cisa: null,
        weaknesses: [],
        affected_cpes: [],
        references: []
      }
    }
  };
});