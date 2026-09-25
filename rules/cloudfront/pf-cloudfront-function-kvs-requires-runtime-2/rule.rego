package cdk_preflight

import rego.v1

_pf_cf_function_kvs_requires_runtime_2_fix := "Set Runtime to cloudfront-js-2.0"

_pf_cf_function_kvs_requires_runtime_2_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-function.html"

violation contains make_diag_full("pf-cloudfront-function-kvs-requires-runtime-2", "ERROR", name, "Properties.FunctionConfig",
	sprintf("a key value store association requires cloudfront-js-2.0, not %v", [rt]),
	_pf_cf_function_kvs_requires_runtime_2_fix, _pf_cf_function_kvs_requires_runtime_2_url) if {
	some name in resources_of_type("AWS::CloudFront::Function")
	fc := _pf_cflib_props(name, "FunctionConfig")
	is_object(fc)
	count(object.get(fc, "KeyValueStoreAssociations", [])) > 0
	rt := object.get(fc, "Runtime", null)
	is_string(rt)
	rt != "cloudfront-js-2.0"
}
