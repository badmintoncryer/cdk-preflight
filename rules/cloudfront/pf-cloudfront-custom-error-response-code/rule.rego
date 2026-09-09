package cdk_preflight

import rego.v1

_pf_cf_custom_error_response_code_fix := "Use 400, 403, 404, 405, 414, 416, 500, 501, 502, 503 or 504"

_pf_cf_custom_error_response_code_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-custom-error-response-code", "ERROR", name, sprintf("Properties.DistributionConfig.CustomErrorResponses.%d", [it.index]),
	sprintf("%v is not an HTTP status code CloudFront can customize", [c]),
	_pf_cf_custom_error_response_code_fix, _pf_cf_custom_error_response_code_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some it in flatten_list(name, "Properties.DistributionConfig.CustomErrorResponses")
	e := it.value
	raw := object.get(e, "ErrorCode", "__pf_absent")
	raw != "__pf_absent"
	c := to_number(raw)
	not c in {400, 403, 404, 405, 414, 416, 500, 501, 502, 503, 504}
}
