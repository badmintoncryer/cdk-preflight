package cdk_preflight

import rego.v1

# CreateKnowledgeBase probes the index with a vector of the model's size; a
# size that differs from the index Dimension fails ("Query vector … is
# invalid for this index", measured 2026-09-06). Only judged when the
# IndexArn is a Fn::GetAtt of an AWS::S3Vectors::Index in the same template.
_pf_kbsd_default := {"amazon.titan-embed-text-v2": 1024, "amazon.titan-embed-text-v1": 1536, "cohere.embed-": 1024}

_pf_kbsd_size(name) := d if {
	d := to_number(resolve(name, "Properties.KnowledgeBaseConfiguration.VectorKnowledgeBaseConfiguration.EmbeddingModelConfiguration.BedrockEmbeddingModelConfiguration.Dimensions"))
}

_pf_kbsd_size(name) := d if {
	not resolve(name, "Properties.KnowledgeBaseConfiguration.VectorKnowledgeBaseConfiguration.EmbeddingModelConfiguration.BedrockEmbeddingModelConfiguration.Dimensions")
	id := _pf_bedrocklib_kb_embed_model(name)
	some prefix, d in _pf_kbsd_default
	startswith(id, prefix)
}

violation contains make_diag_full("pf-bedrock-kb-s3-vectors-index-dimension", "ERROR", name,
	"Properties.StorageConfiguration.S3VectorsConfiguration.IndexArn",
	sprintf("The embeddings are %v-dimensional but index '%s' has Dimension %v; CreateKnowledgeBase fails with \"Query vector … is invalid for this index\"", [kbDim, idx, idxDim]),
	"Create the index with Dimension equal to the embedding size (Titan V2: Dimensions or 1024; Titan G1: 1536; Cohere: 1024)",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent_S3VectorsConfiguration.html") if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	p := _pf_bedrocklib_props(name)
	raw := object.get(object.get(object.get(p, "StorageConfiguration", {}), "S3VectorsConfiguration", {}), "IndexArn", null)
	idx := _pf_bedrocklib_ref_target(raw, "AWS::S3Vectors::Index")
	idxDim := to_number(resolve(idx, "Properties.Dimension"))
	kbDim := _pf_kbsd_size(name)
	kbDim != idxDim
}
