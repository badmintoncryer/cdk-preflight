package cdk_preflight

import rego.v1

_pf_cf_lambda_association_event_type_unique_fix := "Associate at most one function per event type"

_pf_cf_lambda_association_event_type_unique_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-cachebehavior.html"

violation contains make_diag_full("pf-cloudfront-lambda-association-event-type-unique", "ERROR", name, b.path,
	sprintf("EventType %v is associated with more than one Lambda@Edge function", [k]),
	_pf_cf_lambda_association_event_type_unique_fix, _pf_cf_lambda_association_event_type_unique_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cflib_behaviors(name)
	la := object.get(b.value, "LambdaFunctionAssociations", null)
	is_array(la)
	ets := [e | some a in la; e := object.get(a, "EventType", null); is_string(e)]
	some k in ets
	count([x | some x in ets; x == k]) > 1
}
