package cdk_preflight

import rego.v1

# CreateDataSource refuses a WEB connector on any vector store other than
# OpenSearch Serverless (measured 2026-09-06 with S3 Vectors). Judged when
# KnowledgeBaseId references a KnowledgeBase in the same template.
violation contains make_diag_full("pf-bedrock-datasource-web-vector-store", "ERROR", name,
	"Properties.DataSourceConfiguration.Type",
	sprintf("A WEB data source is attached to knowledge base '%s' whose vector store is %s; CreateDataSource fails with \"WEB data source is currently only supported for knowledge bases created with an Amazon OpenSearch Serverless vector database\"", [kb, st]),
	"Use a knowledge base with StorageConfiguration.Type OPENSEARCH_SERVERLESS for web crawling",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/webcrawl-data-source-connector.html") if {
	some name in resources_of_type("AWS::Bedrock::DataSource")
	resolve(name, "Properties.DataSourceConfiguration.Type") == "WEB"
	kb := _pf_bedrocklib_ds_kb(name)
	st := resolve(kb, "Properties.StorageConfiguration.Type")
	is_string(st)
	st != "OPENSEARCH_SERVERLESS"
}
