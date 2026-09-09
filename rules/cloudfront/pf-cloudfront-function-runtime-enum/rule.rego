package cdk_preflight

import rego.v1

_pf_cf_function_runtime_enum_fix := "Use cloudfront-js-2.0"

_pf_cf_function_runtime_enum_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-function.html"

violation contains make_diag_full("pf-cloudfront-function-runtime-enum", "ERROR", name, "Properties.FunctionConfig",
	sprintf("Runtime %v is not a valid CloudFront Functions runtime", [rt]),
	_pf_cf_function_runtime_enum_fix, _pf_cf_function_runtime_enum_url) if {
	some name in resources_of_type("AWS::CloudFront::Function")
	fc := _pf_cflib_props(name, "FunctionConfig")
	is_object(fc)
	rt := object.get(fc, "Runtime", null)
	is_string(rt)
	not rt in {"cloudfront-js-1.0", "cloudfront-js-2.0"}
}
