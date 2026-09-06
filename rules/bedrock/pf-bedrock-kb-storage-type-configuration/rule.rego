package cdk_preflight

import rego.v1

# The schema's oneOf guarantees exactly one vector-store block but not that it
# is the one named by Type; CreateKnowledgeBase requires the pairing
# ("<Block> is required when storage type is <Type>", measured 2026-09-06).
_pf_kbst_member := {
	"OPENSEARCH_SERVERLESS": "OpensearchServerlessConfiguration",
	"PINECONE": "PineconeConfiguration",
	"RDS": "RdsConfiguration",
	"MONGO_DB_ATLAS": "MongoDbAtlasConfiguration",
	"NEPTUNE_ANALYTICS": "NeptuneAnalyticsConfiguration",
	"S3_VECTORS": "S3VectorsConfiguration",
	"OPENSEARCH_MANAGED_CLUSTER": "OpensearchManagedClusterConfiguration",
}

violation contains make_diag_full("pf-bedrock-kb-storage-type-configuration", "ERROR", name,
	sprintf("Properties.StorageConfiguration.%s", [m]),
	sprintf("StorageConfiguration.Type is %s but %s is missing; CreateKnowledgeBase fails with \"%s is required when storage type is %s\"", [t, m, m, t]),
	sprintf("Add StorageConfiguration.%s, or change Type to match the block you configured", [m]),
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_CreateKnowledgeBase.html") if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	sc := object.get(_pf_bedrocklib_props(name), "StorageConfiguration", null)
	is_object(sc)
	t := sc.Type
	m := _pf_kbst_member[t]
	not _pf_bedrocklib_has(sc, m)
}
