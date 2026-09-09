package cdk_preflight

import rego.v1

_pf_cf_lambda_association_include_body_event_type_fix := "Drop IncludeBody, or move the association to a request event type"

_pf_cf_lambda_association_include_body_event_type_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-cachebehavior.html"

violation contains make_diag_full("pf-cloudfront-lambda-association-include-body-event-type", "ERROR", name, b.path,
	sprintf("IncludeBody cannot be set on the %v event type", [et]),
	_pf_cf_lambda_association_include_body_event_type_fix, _pf_cf_lambda_association_include_body_event_type_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cflib_behaviors(name)
	la := object.get(b.value, "LambdaFunctionAssociations", null)
	is_array(la)
	some a in la
	object.get(a, "IncludeBody", false) == true
	et := object.get(a, "EventType", null)
	is_string(et)
	not et in {"viewer-request", "origin-request"}
}
