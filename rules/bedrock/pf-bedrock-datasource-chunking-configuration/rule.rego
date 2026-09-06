package cdk_preflight

import rego.v1

# The schema requires only ChunkingStrategy; CreateDataSource requires the
# block named after it for FIXED_SIZE / HIERARCHICAL / SEMANTIC (measured
# 2026-09-06; NONE takes no block but tolerates one).
_pf_dscc_member := {"FIXED_SIZE": "FixedSizeChunkingConfiguration", "HIERARCHICAL": "HierarchicalChunkingConfiguration", "SEMANTIC": "SemanticChunkingConfiguration"}

violation contains make_diag_full("pf-bedrock-datasource-chunking-configuration", "ERROR", name,
	sprintf("Properties.VectorIngestionConfiguration.ChunkingConfiguration.%s", [m]),
	sprintf("ChunkingStrategy is %s but %s is missing; CreateDataSource fails with \"%s%s is required when chunking strategy is %s\"", [t, m, lower(substring(m, 0, 1)), substring(m, 1, -1), t]),
	sprintf("Add ChunkingConfiguration.%s", [m]),
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_ChunkingConfiguration.html") if {
	some name in resources_of_type("AWS::Bedrock::DataSource")
	cc := object.get(object.get(_pf_bedrocklib_props(name), "VectorIngestionConfiguration", {}), "ChunkingConfiguration", null)
	is_object(cc)
	t := cc.ChunkingStrategy
	m := _pf_dscc_member[t]
	not _pf_bedrocklib_has(cc, m)
}
