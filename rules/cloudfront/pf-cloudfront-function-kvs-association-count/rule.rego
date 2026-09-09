package cdk_preflight

import rego.v1

_pf_cf_function_kvs_association_count_fix := "Associate a single key value store"

_pf_cf_function_kvs_association_count_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-function.html"

violation contains make_diag_full("pf-cloudfront-function-kvs-association-count", "ERROR", name, "Properties.FunctionConfig",
	sprintf("%v key value stores are associated; the limit is 1", [count(kvs)]),
	_pf_cf_function_kvs_association_count_fix, _pf_cf_function_kvs_association_count_url) if {
	some name in resources_of_type("AWS::CloudFront::Function")
	fc := _pf_cflib_props(name, "FunctionConfig")
	is_object(fc)
	kvs := object.get(fc, "KeyValueStoreAssociations", [])
	count(kvs) > 1
}
