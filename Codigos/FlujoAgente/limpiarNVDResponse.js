return $input.all().map(item => {
  const nvd = item.json;

  const vulnerability = Array.isArray(nvd.vulnerabilities)
    ? nvd.vulnerabilities[0]
    : null;

  const cve = vulnerability?.cve || null;
  const cveId = cve?.id || null;

  if (!cve) {
    return {
      json: {
        merge_key: null,
        nvd_meta: {
          total_results: nvd.totalResults || 0,
          timestamp: nvd.timestamp || null
        },
        cve_data: {
          found_in_nvd: false,
          id: null,
          source: null,
          published: null,
          last_modified: null,
          status: "not_found",
          description: null,
          cvss: null,
          cisa: {
            exploit_add: null,
            action_due: null,
            required_action: null,
            vulnerability_name: null
          },
          affected_cpes: [],
          weaknesses: [],
          references: []
        }
      }
    };
  }

  const description =
    (cve.descriptions || []).find(d => d.lang === "en")?.value ||
    (cve.descriptions || [])[0]?.value ||
    null;

  const metrics = cve.metrics || {};

  function pickMetric(list) {
    if (!Array.isArray(list) || list.length === 0) return null;
    return list.find(m => m.type === "Primary") || list[0];
  }

  const cvssMetric =
    pickMetric(metrics.cvssMetricV40) ||
    pickMetric(metrics.cvssMetricV31) ||
    pickMetric(metrics.cvssMetricV30) ||
    pickMetric(metrics.cvssMetricV2) ||
    null;

  const cvssData = cvssMetric?.cvssData || null;

  const references = (cve.references || [])
    .map(ref => ({
      url: ref.url || null,
      source: ref.source || null,
      tags: ref.tags || []
    }))
    .filter(ref => ref.url);

  const weaknesses = [];

  for (const w of cve.weaknesses || []) {
    for (const d of w.description || []) {
      if (d.value) {
        weaknesses.push({
          source: w.source || null,
          type: w.type || null,
          value: d.value
        });
      }
    }
  }

  const affectedCpes = [];

  function walkNode(node) {
    if (!node) return;

    if (Array.isArray(node.cpeMatch)) {
      for (const match of node.cpeMatch) {
        if (match.vulnerable !== true) continue;

        affectedCpes.push({
          criteria: match.criteria || null,
          version_start_including: match.versionStartIncluding || null,
          version_start_excluding: match.versionStartExcluding || null,
          version_end_including: match.versionEndIncluding || null,
          version_end_excluding: match.versionEndExcluding || null
        });
      }
    }

    if (Array.isArray(node.nodes)) {
      node.nodes.forEach(walkNode);
    }

    if (Array.isArray(node.children)) {
      node.children.forEach(walkNode);
    }
  }

  for (const configuration of cve.configurations || []) {
    if (Array.isArray(configuration.nodes)) {
      configuration.nodes.forEach(walkNode);
    }
  }

  return {
    json: {
      merge_key: cveId,
      nvd_meta: {
        total_results: nvd.totalResults || 0,
        timestamp: nvd.timestamp || null
      },
      cve_data: {
        found_in_nvd: true,
        id: cveId,
        source: cve.sourceIdentifier || null,
        published: cve.published || null,
        last_modified: cve.lastModified || null,
        status: cve.vulnStatus || null,
        description,

        cvss: cvssData
          ? {
              version: cvssData.version || null,
              score: cvssData.baseScore ?? null,
              severity: cvssData.baseSeverity || cvssMetric?.baseSeverity || null,
              vector: cvssData.vectorString || null,
              attack_vector: cvssData.attackVector || cvssData.accessVector || null,
              attack_complexity: cvssData.attackComplexity || cvssData.accessComplexity || null,
              privileges_required: cvssData.privilegesRequired || null,
              user_interaction: cvssData.userInteraction || null,
              confidentiality_impact: cvssData.confidentialityImpact || null,
              integrity_impact: cvssData.integrityImpact || null,
              availability_impact: cvssData.availabilityImpact || null,
              source: cvssMetric?.source || null,
              type: cvssMetric?.type || null
            }
          : null,

        cisa: {
          exploit_add: cve.cisaExploitAdd || null,
          action_due: cve.cisaActionDue || null,
          required_action: cve.cisaRequiredAction || null,
          vulnerability_name: cve.cisaVulnerabilityName || null
        },

        weaknesses,
        affected_cpes: affectedCpes,
        references
      }
    }
  };
});