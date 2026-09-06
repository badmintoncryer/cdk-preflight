package cdk_preflight

import rego.v1

# StorageConfiguration is optional in the schema because KENDRA / SQL / MANAGED
# knowledge bases have none; a VECTOR one cannot be created without it
# (measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-kb-vector-storage-required", "ERROR", name,
	"Properties.StorageConfiguration",
	"A VECTOR knowledge base has no StorageConfiguration; CreateKnowledgeBase fails with \"You must provide a storage configuration if you create a VECTOR knowledge base\"",
	"Add StorageConfiguration (Type OPENSEARCH_SERVERLESS, S3_VECTORS, RDS, …) pointing at the vector store",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_CreateKnowledgeBase.html") if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	p := _pf_bedrocklib_props(name)
	resolve(name, "Properties.KnowledgeBaseConfiguration.Type") == "VECTOR"
	not _pf_bedrocklib_has(p, "StorageConfiguration")
}
