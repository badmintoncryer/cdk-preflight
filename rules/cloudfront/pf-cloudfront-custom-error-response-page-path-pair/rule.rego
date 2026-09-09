package cdk_preflight

import rego.v1

_pf_cf_custom_error_response_page_path_pair_fix := "Set both ResponsePagePath and ResponseCode, or neither"

_pf_cf_custom_error_response_page_path_pair_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-custom-error-response-page-path-pair", "ERROR", name, sprintf("Properties.DistributionConfig.CustomErrorResponses.%d", [it.index]),
	"ResponsePagePath is set but ResponseCode is missing",
	_pf_cf_custom_error_response_page_path_pair_fix, _pf_cf_custom_error_response_page_path_pair_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some it in flatten_list(name, "Properties.DistributionConfig.CustomErrorResponses")
	e := it.value
	object.get(e, "ResponsePagePath", "__pf_absent") != "__pf_absent"
	object.get(e, "ResponseCode", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-cloudfront-custom-error-response-page-path-pair", "ERROR", name, sprintf("Properties.DistributionConfig.CustomErrorResponses.%d", [it.index]),
	"ResponseCode is set but ResponsePagePath is missing",
	_pf_cf_custom_error_response_page_path_pair_fix, _pf_cf_custom_error_response_page_path_pair_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some it in flatten_list(name, "Properties.DistributionConfig.CustomErrorResponses")
	e := it.value
	object.get(e, "ResponseCode", "__pf_absent") != "__pf_absent"
	object.get(e, "ResponsePagePath", "__pf_absent") == "__pf_absent"
}
