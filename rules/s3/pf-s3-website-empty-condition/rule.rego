package cdk_preflight

import rego.v1

_pf_s3wec_fix := "Give the condition KeyPrefixEquals or HttpErrorCodeReturnedEquals, or drop it"

_pf_s3wec_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-routingrule.html"

violation contains make_diag_full("pf-s3-website-empty-condition", "ERROR", name,
	sprintf("Properties.WebsiteConfiguration.RoutingRules.%d.RoutingRuleCondition", [r.index]),
	"the routing rule condition sets neither KeyPrefixEquals nor HttpErrorCodeReturnedEquals",
	_pf_s3wec_fix, _pf_s3wec_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some r in flatten_list(name, "Properties.WebsiteConfiguration.RoutingRules")
	is_object(r.value)
	c := object.get(r.value, "RoutingRuleCondition", "__pf_absent")
	is_object(c)
	object.get(c, "KeyPrefixEquals", "__pf_absent") == "__pf_absent"
	object.get(c, "HttpErrorCodeReturnedEquals", "__pf_absent") == "__pf_absent"
}
