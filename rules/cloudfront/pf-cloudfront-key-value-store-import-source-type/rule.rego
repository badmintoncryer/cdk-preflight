package cdk_preflight

import rego.v1

_pf_cf_key_value_store_import_source_type_fix := "Set SourceType to S3"

_pf_cf_key_value_store_import_source_type_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-keyvaluestore.html"

violation contains make_diag_full("pf-cloudfront-key-value-store-import-source-type", "ERROR", name, "Properties.ImportSource",
	sprintf("SourceType %v is not supported; only S3 is", [st]),
	_pf_cf_key_value_store_import_source_type_fix, _pf_cf_key_value_store_import_source_type_url) if {
	some name in resources_of_type("AWS::CloudFront::KeyValueStore")
	is := _pf_cflib_props(name, "ImportSource")
	is_object(is)
	st := object.get(is, "SourceType", null)
	is_string(st)
	st != "S3"
}
