package cdk_preflight

import rego.v1

# Both orderings are enforced only by CreateDataSource (measured 2026-09-06):
# parent MaxTokens > child MaxTokens, and OverlapTokens < child MaxTokens.
_pf_dshl_url := "https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_HierarchicalChunkingConfiguration.html"
_pf_dshl_path := "Properties.VectorIngestionConfiguration.ChunkingConfiguration.HierarchicalChunkingConfiguration"

_pf_dshl_cfg(name) := h if {
	p := _pf_bedrocklib_props(name)
	h := object.get(object.get(object.get(p, "VectorIngestionConfiguration", {}), "ChunkingConfiguration", {}), "HierarchicalChunkingConfiguration", null)
	is_object(h)
}

_pf_dshl_levels(name) := [parent, child] if {
	ls := object.get(_pf_dshl_cfg(name), "LevelConfigurations", [])
	_pf_countable_items(ls)
	count(ls) == 2
	parent := _pf_tonum(ls[0].MaxTokens)
	child := _pf_tonum(ls[1].MaxTokens)
}

violation contains make_diag_full("pf-bedrock-datasource-hierarchical-levels", "ERROR", name,
	sprintf("%s.LevelConfigurations", [_pf_dshl_path]),
	sprintf("Parent level MaxTokens %v is not larger than child level MaxTokens %v; CreateDataSource fails with \"Max tokens for each level in hierarchical chunking must be in descending order\"", [l[0], l[1]]),
	"Give the first (parent) level a larger MaxTokens than the second (child) level",
	_pf_dshl_url) if {
	some name in resources_of_type("AWS::Bedrock::DataSource")
	l := _pf_dshl_levels(name)
	l[0] <= l[1]
}

violation contains make_diag_full("pf-bedrock-datasource-hierarchical-levels", "ERROR", name,
	sprintf("%s.OverlapTokens", [_pf_dshl_path]),
	sprintf("OverlapTokens %v is not smaller than the child level MaxTokens %v; CreateDataSource fails with \"Overlap tokens … must be smaller than the bottom level max tokens\"", [o, l[1]]),
	"Lower OverlapTokens below the child level MaxTokens",
	_pf_dshl_url) if {
	some name in resources_of_type("AWS::Bedrock::DataSource")
	l := _pf_dshl_levels(name)
	o := _pf_onum(_pf_dshl_cfg(name), "OverlapTokens")
	o >= l[1]
}
