package cdk_preflight

import rego.v1

_pf_cf_key_value_store_import_source_arn_fix := "Use arn:aws:s3:::<bucket>/<key>, not an s3:// URL"

_pf_cf_key_value_store_import_source_arn_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-keyvaluestore.html"

violation contains make_diag_full("pf-cloudfront-key-value-store-import-source-arn", "ERROR", name, "Properties.ImportSource",
	sprintf("SourceArn %v is not an S3 object ARN", [sa]),
	_pf_cf_key_value_store_import_source_arn_fix, _pf_cf_key_value_store_import_source_arn_url) if {
	some name in resources_of_type("AWS::CloudFront::KeyValueStore")
	is := _pf_cflib_props(name, "ImportSource")
	is_object(is)
	sa := object.get(is, "SourceArn", null)
	is_string(sa)
	sa != ""
	not regex.match("^arn:[a-z0-9-]+:s3:::.+/.+", sa)
}
