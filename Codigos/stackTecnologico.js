const companyStack = [
  {
    name: "Spring AI",
    vendor: "VMware",
    versions: ["1.0.5"],
    deployment: "self-hosted",
    exposure: "internal",
    criticality: "medium",
    active: true
  },
  {
    name: "n8n",
    vendor: "n8n",
    versions: ["2.8.3"],
    deployment: "self-hosted",
    exposure: "internal",
    criticality: "medium",
    active: true
  },
  {
    name: "PostgreSQL",
    vendor: "PostgreSQL",
    versions: ["15.13"],
    deployment: "self-hosted",
    exposure: "internal",
    criticality: "high",
    active: true
  },
  {
    name: "Ollama",
    vendor: "Ollama",
    versions: [],
    deployment: "local",
    exposure: "local",
    criticality: "low",
    active: true
  }
];

return $input.all().map(item => {
  return {
    json: {
      ...item.json,
      company_stack: companyStack
    }
  };
});