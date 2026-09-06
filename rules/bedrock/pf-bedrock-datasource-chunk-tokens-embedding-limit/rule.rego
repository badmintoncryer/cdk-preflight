package cdk_preflight

import rego.v1

# Cohere Embed accepts 512 tokens per chunk (Titan 8192, which the API cap
# already enforces); CreateDataSource checks the fixed / semantic size and the
# hierarchical child level against the knowledge base's model (measured
# 2026-09-06). Judged when KnowledgeBaseId references a KnowledgeBase in the
# same template.
_pf_dsel_limit := {"cohere.embed-": 512}

_pf_dsel_prefix := "Properties.VectorIngestionConfiguration.ChunkingConfiguration"

_pf_dsel_paths := [sprintf("%s.FixedSizeChunkingConfiguration.MaxTokens", [_pf_dsel_prefix]), sprintf("%s.SemanticChunkingConfiguration.MaxTokens", [_pf_dsel_prefix]), sprintf("%s.HierarchicalChunkingConfiguration.LevelConfigurations[1].MaxTokens", [_pf_dsel_prefix])]

_pf_dsel_cc(name) := cc if {
	cc := object.get(object.get(_pf_bedrocklib_props(name), "VectorIngestionConfiguration", {}), "ChunkingConfiguration", null)
	is_object(cc)
}

# Chunk size CreateDataSource checks for a given property path.
_pf_dsel_size(name, path) := n if {
	path == _pf_dsel_paths[0]
	n := to_number(object.get(object.get(_pf_dsel_cc(name), "FixedSizeChunkingConfiguration", {}), "MaxTokens", null))
}

_pf_dsel_size(name, path) := n if {
	path == _pf_dsel_paths[1]
	n := to_number(object.get(object.get(_pf_dsel_cc(name), "SemanticChunkingConfiguration", {}), "MaxTokens", null))
}

_pf_dsel_size(name, path) := n if {
	path == _pf_dsel_paths[2]
	ls := object.get(object.get(_pf_dsel_cc(name), "HierarchicalChunkingConfiguration", {}), "LevelConfigurations", [])
	count(ls) == 2
	n := to_number(ls[1].MaxTokens)
}

violation contains make_diag_full("pf-bedrock-datasource-chunk-tokens-embedding-limit", "ERROR", name,
	path,
	sprintf("MaxTokens %v exceeds the %v-token limit of embedding model %s (knowledge base '%s'); CreateDataSource fails with \"exceeds the embedding model … limit\"", [n, limit, model, kb]),
	"Lower the chunk size to the embedding model's limit (512 tokens for Cohere Embed)",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-supported.html") if {
	some name in resources_of_type("AWS::Bedrock::DataSource")
	kb := _pf_bedrocklib_ds_kb(name)
	model := _pf_bedrocklib_kb_embed_model(kb)
	some prefix, limit in _pf_dsel_limit
	startswith(model, prefix)
	some path in _pf_dsel_paths
	n := _pf_dsel_size(name, path)
	n > limit
}
