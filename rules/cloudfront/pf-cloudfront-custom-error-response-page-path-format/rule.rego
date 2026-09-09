package cdk_preflight

import rego.v1

_pf_cf_custom_error_response_page_path_format_fix := "Write the custom error page path as /404.html"

_pf_cf_custom_error_response_page_path_format_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-custom-error-response-page-path-format", "ERROR", name, sprintf("Properties.DistributionConfig.CustomErrorResponses.%d", [it.index]),
	sprintf("ResponsePagePath %v does not start with /", [pp]),
	_pf_cf_custom_error_response_page_path_format_fix, _pf_cf_custom_error_response_page_path_format_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some it in flatten_list(name, "Properties.DistributionConfig.CustomErrorResponses")
	e := it.value
	pp := object.get(e, "ResponsePagePath", null)
	is_string(pp)
	not startswith(pp, "/")
}
