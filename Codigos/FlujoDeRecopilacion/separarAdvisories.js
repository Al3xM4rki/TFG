const output = [];

for (const item of $input.all()) {
  const nodes = item.json?.data?.securityAdvisories?.nodes || [];

  for (const advisory of nodes) {
    output.push({
      json: advisory
    });
  }
}

return output;