package cdk_preflight

import rego.v1

# CreateKnowledgeBase rejects an embedding model ARN of another Region ("is in
# a different region", measured 2026-09-06). Needs deploy_region.
violation contains make_diag_full("pf-bedrock-kb-embedding-model-region", "ERROR", name,
	"Properties.KnowledgeBaseConfiguration.VectorKnowledgeBaseConfiguration.EmbeddingModelArn",
	sprintf("The embedding model ARN names Region '%s' but the knowledge base deploys to '%s'; CreateKnowledgeBase fails with \"The embedding model ARN … is in a different region\"", [r, region]),
	"Build the ARN with ${AWS::Region} (arn:${AWS::Partition}:bedrock:${AWS::Region}::foundation-model/<id>)",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_CreateKnowledgeBase.html") if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	region := _pf_bedrocklib_region
	arn := resolve(name, "Properties.KnowledgeBaseConfiguration.VectorKnowledgeBaseConfiguration.EmbeddingModelArn")
	r := _pf_bedrocklib_arn_region(arn)
	r != region
}
