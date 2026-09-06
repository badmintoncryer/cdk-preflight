package cdk_preflight

import rego.v1

# Images extracted by a multimodal parser need a place to live; CreateDataSource
# rejects MULTIMODAL parsing when the knowledge base has no supplemental data
# storage (measured 2026-09-06). Judged when KnowledgeBaseId references a
# KnowledgeBase in the same template.
_pf_dsms_paths := ["Properties.VectorIngestionConfiguration.ParsingConfiguration.BedrockFoundationModelConfiguration.ParsingModality", "Properties.VectorIngestionConfiguration.ParsingConfiguration.BedrockDataAutomationConfiguration.ParsingModality"]

violation contains make_diag_full("pf-bedrock-datasource-multimodal-supplemental-storage", "ERROR", name,
	path,
	sprintf("ParsingModality MULTIMODAL is used with knowledge base '%s', which has no SupplementalDataStorageConfiguration; CreateDataSource fails with \"Knowledge base must have supplementalDataStorageConfiguration to use specified parsing configuration\"", [kb]),
	"Add VectorKnowledgeBaseConfiguration.SupplementalDataStorageConfiguration (an S3 bucket root, separate from the data bucket) to the knowledge base",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/kb-multimodal.html") if {
	some name in resources_of_type("AWS::Bedrock::DataSource")
	some path in _pf_dsms_paths
	resolve(name, path) == "MULTIMODAL"
	kb := _pf_bedrocklib_ds_kb(name)
	vc := object.get(object.get(_pf_bedrocklib_props(kb), "KnowledgeBaseConfiguration", {}), "VectorKnowledgeBaseConfiguration", null)
	is_object(vc)
	not _pf_bedrocklib_has(vc, "SupplementalDataStorageConfiguration")
}
