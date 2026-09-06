package cdk_preflight

import rego.v1

# The schema requires only Type; CreateKnowledgeBase requires the block named
# after it for VECTOR / KENDRA / SQL ("<Block> is required when knowledgeBase
# type is <Type>", measured 2026-09-06; MANAGED has no such requirement).
_pf_kbtc_member := {"VECTOR": "VectorKnowledgeBaseConfiguration", "KENDRA": "KendraKnowledgeBaseConfiguration", "SQL": "SqlKnowledgeBaseConfiguration"}

violation contains make_diag_full("pf-bedrock-kb-type-configuration", "ERROR", name,
	sprintf("Properties.KnowledgeBaseConfiguration.%s", [m]),
	sprintf("KnowledgeBaseConfiguration.Type is %s but %s is missing; CreateKnowledgeBase fails with \"%s is required when knowledgeBase type is %s\"", [t, m, m, t]),
	sprintf("Add KnowledgeBaseConfiguration.%s, or change Type", [m]),
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_CreateKnowledgeBase.html") if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	cfg := object.get(_pf_bedrocklib_props(name), "KnowledgeBaseConfiguration", null)
	is_object(cfg)
	t := cfg.Type
	m := _pf_kbtc_member[t]
	not _pf_bedrocklib_has(cfg, m)
}
