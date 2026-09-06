package cdk_preflight

import rego.v1

# Binary vectors are supported by Titan Text Embeddings V2 and Cohere Embed
# but not by Titan Embeddings G1 - Text, and S3 Vectors indexes store float32
# only (both measured 2026-09-06).
_pf_kbeb_url := "https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-supported.html"
_pf_kbeb_path := "Properties.KnowledgeBaseConfiguration.VectorKnowledgeBaseConfiguration.EmbeddingModelConfiguration.BedrockEmbeddingModelConfiguration.EmbeddingDataType"

violation contains make_diag_full("pf-bedrock-kb-embedding-binary", "ERROR", name,
	_pf_kbeb_path,
	"EmbeddingDataType BINARY is combined with an S3_VECTORS store; CreateKnowledgeBase fails with \"The embedding type provided BINARY is invalid for storage type S3_VECTORS\"",
	"Use FLOAT32 embeddings with S3 Vectors, or a vector store that accepts binary vectors (e.g. OpenSearch Serverless)",
	_pf_kbeb_url) if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	resolve(name, _pf_kbeb_path) == "BINARY"
	resolve(name, "Properties.StorageConfiguration.Type") == "S3_VECTORS"
}

violation contains make_diag_full("pf-bedrock-kb-embedding-binary", "ERROR", name,
	_pf_kbeb_path,
	sprintf("EmbeddingDataType BINARY is not supported by %s; CreateKnowledgeBase fails with \"embeddingDataType BINARY not supported for embedding model\"", [id]),
	"Use FLOAT32, or switch to Titan Text Embeddings V2 / Cohere Embed which support binary vectors",
	_pf_kbeb_url) if {
	some name in resources_of_type("AWS::Bedrock::KnowledgeBase")
	resolve(name, _pf_kbeb_path) == "BINARY"
	id := _pf_bedrocklib_kb_embed_model(name)
	startswith(id, "amazon.titan-embed-text-v1")
}
