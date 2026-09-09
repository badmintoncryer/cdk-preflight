package cdk_preflight

import rego.v1

_pf_cf_function_association_event_type_fix := "Use viewer-request or viewer-response, or switch to Lambda@Edge"

_pf_cf_function_association_event_type_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-cachebehavior.html"

violation contains make_diag_full("pf-cloudfront-function-association-event-type", "ERROR", name, b.path,
	sprintf("FunctionAssociations cannot use the origin-facing event type %v", [et]),
	_pf_cf_function_association_event_type_fix, _pf_cf_function_association_event_type_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cflib_behaviors(name)
	fa := object.get(b.value, "FunctionAssociations", null)
	is_array(fa)
	some a in fa
	et := object.get(a, "EventType", null)
	is_string(et)
	not et in {"viewer-request", "viewer-response"}
}
