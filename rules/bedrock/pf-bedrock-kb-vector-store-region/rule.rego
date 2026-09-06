package cdk_preflight

import rego.v1

# CreateKnowledgeBase requires the vector store to be in its own Region ("The
# vector store must be in the same region as the knowledge base", measured
# 2026-09-06 with S3 Vectors). Needs deploy_region.
_pf_kbvr_paths := ["Properties.StorageConfiguration.S3VectorsConfiguration.IndexArn", "Properties.StorageConfiguration.S3VectorsConfiguration.VectorBucketArn"]

violation contains make_diag_full("pf-bedrock-kb-vector-store-region", "ERROR", name,
	path,
	sprintf("The vector store ARN names Region '%s' but the knowledge base deploys to '%s'; CreateKnowledgeBase fails with \"The vector store must be in the same region as the knowledge base\"", [r, region]),
	"Reference an S3 Vectors bucket / index created in the knowledge base's own Region",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_S3VectorsConfiguration.html") if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	region := _pf_bedrocklib_region
	some path in _pf_kbvr_paths
	r := _pf_bedrocklib_arn_region(resolve(name, path))
	r != region
}
