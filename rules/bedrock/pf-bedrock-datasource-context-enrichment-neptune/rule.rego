package cdk_preflight

import rego.v1

# GraphRAG entity extraction only exists for Neptune Analytics stores;
# CreateDataSource rejects the block on any other vector store (measured
# 2026-09-06). Judged when KnowledgeBaseId references a KnowledgeBase in the
# same template.
violation contains make_diag_full("pf-bedrock-datasource-context-enrichment-neptune", "ERROR", name,
	"Properties.VectorIngestionConfiguration.ContextEnrichmentConfiguration",
	sprintf("ContextEnrichmentConfiguration is set but knowledge base '%s' stores vectors in %s; CreateDataSource fails with \"ContextEnrichmentConfiguration is only supported when using Neptune Analytics as a Knowledge Base\"", [kb, st]),
	"Remove ContextEnrichmentConfiguration, or use a knowledge base with StorageConfiguration.Type NEPTUNE_ANALYTICS",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_ContextEnrichmentConfiguration.html") if {
	some name in resources_of_type("AWS::Bedrock::DataSource")
	_pf_bedrocklib_has(object.get(_pf_bedrocklib_props(name), "VectorIngestionConfiguration", {}), "ContextEnrichmentConfiguration")
	kb := _pf_bedrocklib_ds_kb(name)
	st := resolve(kb, "Properties.StorageConfiguration.Type")
	is_string(st)
	st != "NEPTUNE_ANALYTICS"
}
