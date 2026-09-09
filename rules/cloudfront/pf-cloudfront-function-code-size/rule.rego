package cdk_preflight

import rego.v1

_pf_cf_function_code_size_fix := "Shorten the function code to 10240 bytes or fewer"

_pf_cf_function_code_size_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudfront-function.html"

violation contains make_diag_full("pf-cloudfront-function-code-size", "ERROR", name, "Properties.FunctionCode",
	sprintf("FunctionCode is %v bytes, over the 10240 limit", [count(code)]),
	_pf_cf_function_code_size_fix, _pf_cf_function_code_size_url) if {
	some name in resources_of_type("AWS::CloudFront::Function")
	code := resolve(name, "Properties.FunctionCode")
	is_string(code)
	count(code) > 10240
}
