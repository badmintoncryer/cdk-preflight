package cdk_preflight

import rego.v1

# Kendra and structured-data knowledge bases bring their own store; CreateKnowledgeBase
# rejects a StorageConfiguration next to them (measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-kb-storage-not-allowed", "ERROR", name,
	"Properties.StorageConfiguration",
	sprintf("A %s knowledge base carries StorageConfiguration; CreateKnowledgeBase fails with \"You can't provide a storage configuration if the type of your knowledge base is %s\"", [t, t]),
	"Remove StorageConfiguration (the Kendra index / Redshift store is configured inside KnowledgeBaseConfiguration)",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_CreateKnowledgeBase.html") if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	t := resolve(name, "Properties.KnowledgeBaseConfiguration.Type")
	t in {"KENDRA", "SQL"}
	_pf_bedrocklib_has(_pf_bedrocklib_props(name), "StorageConfiguration")
}
