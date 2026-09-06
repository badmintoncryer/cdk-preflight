package cdk_preflight

import rego.v1

# Extracted media written back into the data bucket would be re-ingested, so
# CreateDataSource refuses the overlap unless InclusionPrefixes narrows the
# crawl (measured 2026-09-06). Buckets are compared as literal names or as
# the same in-template bucket (Ref / GetAtt / ${Bucket} in a Fn::Sub).
_pf_dssb_bucket(v) := b if {
	b := _pf_bedrocklib_bucket_expr(v)
}

_pf_dssb_bucket(v) := b if {
	is_object(v)
	ref := object.get(v, "__ref", null)
	is_string(ref)
	b := sprintf("${%s}", [ref])
}

_pf_dssb_norm(b) := replace(b, ".Arn}", "}")

violation contains make_diag_full("pf-bedrock-datasource-supplemental-bucket-overlap", "ERROR", name,
	"Properties.DataSourceConfiguration.S3Configuration.BucketArn",
	sprintf("The data source bucket is also the supplemental data storage of knowledge base '%s' and no InclusionPrefixes is set; CreateDataSource fails with \"Your data source and multimodal storage destination use the same S3 bucket\"", [kb]),
	"Use a separate bucket for supplemental data storage, or set S3Configuration.InclusionPrefixes",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/kb-multimodal.html") if {
	some name in resources_of_type("AWS::Bedrock::DataSource")
	p := _pf_bedrocklib_props(name)
	s3 := object.get(object.get(p, "DataSourceConfiguration", {}), "S3Configuration", null)
	is_object(s3)
	not _pf_bedrocklib_has(s3, "InclusionPrefixes")
	dsb := _pf_dssb_norm(_pf_dssb_bucket(object.get(s3, "BucketArn", null)))
	kb := _pf_bedrocklib_ds_kb(name)
	locs := object.get(object.get(object.get(object.get(_pf_bedrocklib_props(kb), "KnowledgeBaseConfiguration", {}), "VectorKnowledgeBaseConfiguration", {}), "SupplementalDataStorageConfiguration", {}), "SupplementalDataStorageLocations", [])
	some l in locs
	is_object(l)
	sb := _pf_dssb_norm(_pf_dssb_bucket(object.get(object.get(l, "S3Location", {}), "URI", null)))
	sb == dsb
}
