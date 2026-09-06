package cdk_preflight

import rego.v1

# The API caps maxTokens at 8192 for fixed-size and semantic chunking; the
# schema carries the cap only for the hierarchical levels (measured 2026-09-06).
_pf_dsmt_paths := ["Properties.VectorIngestionConfiguration.ChunkingConfiguration.FixedSizeChunkingConfiguration.MaxTokens", "Properties.VectorIngestionConfiguration.ChunkingConfiguration.SemanticChunkingConfiguration.MaxTokens"]

violation contains make_diag_full("pf-bedrock-datasource-chunk-max-tokens", "ERROR", name,
	path,
	sprintf("MaxTokens %v exceeds the 8192-token maximum; CreateDataSource fails with \"Member must have value less than or equal to 8192\"", [n]),
	"Use at most 8192 tokens per chunk (and no more than the embedding model accepts)",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_FixedSizeChunkingConfiguration.html") if {
	some name in resources_of_type("AWS::Bedrock::DataSource")
	some path in _pf_dsmt_paths
	n := to_number(resolve(name, path))
	n > 8192
}
