package cdk_preflight

import rego.v1

# Supported vector sizes per model (knowledge-base-supported.html, 2026-09-06):
# Titan Text Embeddings V2 256/512/1024, Titan Embeddings G1 - Text fixed 1536
# (no configurable dimensions), Cohere Embed 1024. The schema allows 0..4096.
_pf_kbed_sizes := {"amazon.titan-embed-text-v2": {256, 512, 1024}, "cohere.embed-english-v3": {1024}, "cohere.embed-multilingual-v3": {1024}}

_pf_kbed_family(id) := f if {
	some f, _ in _pf_kbed_sizes
	startswith(id, f)
}

_pf_kbed_url := "https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-supported.html"
_pf_kbed_path := "Properties.KnowledgeBaseConfiguration.VectorKnowledgeBaseConfiguration.EmbeddingModelConfiguration.BedrockEmbeddingModelConfiguration.Dimensions"

violation contains make_diag_full("pf-bedrock-kb-embedding-dimensions", "ERROR", name,
	_pf_kbed_path,
	sprintf("Dimensions %v is not supported by %s (allowed: %v); CreateKnowledgeBase fails with \"The specified embedding dimensions is not supported by the model\"", [d, id, _pf_kbed_sizes[f]]),
	"Pick one of the model's supported vector sizes",
	_pf_kbed_url) if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	id := _pf_bedrocklib_kb_embed_model(name)
	f := _pf_kbed_family(id)
	d := to_number(resolve(name, _pf_kbed_path))
	not _pf_kbed_sizes[f][d]
}

violation contains make_diag_full("pf-bedrock-kb-embedding-dimensions", "ERROR", name,
	_pf_kbed_path,
	sprintf("%s has a fixed 1536-dimension output; CreateKnowledgeBase fails with \"The specified model … does not support configurable dimensions\"", [id]),
	"Remove Dimensions, or switch to Titan Text Embeddings V2 (256/512/1024)",
	_pf_kbed_url) if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	id := _pf_bedrocklib_kb_embed_model(name)
	startswith(id, "amazon.titan-embed-text-v1")
	resolve(name, _pf_kbed_path)
}
