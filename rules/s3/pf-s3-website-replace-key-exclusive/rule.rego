package cdk_preflight

import rego.v1

_pf_s3wrk_fix := "Keep either ReplaceKeyWith or ReplaceKeyPrefixWith in the redirect rule"

_pf_s3wrk_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-routingrule.html"

violation contains make_diag_full("pf-s3-website-replace-key-exclusive", "ERROR", name,
	sprintf("Properties.WebsiteConfiguration.RoutingRules.%d.RedirectRule", [r.index]),
	"the redirect rule sets both ReplaceKeyWith and ReplaceKeyPrefixWith; S3 accepts only one",
	_pf_s3wrk_fix, _pf_s3wrk_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some r in flatten_list(name, "Properties.WebsiteConfiguration.RoutingRules")
	is_object(r.value)
	rr := object.get(r.value, "RedirectRule", {})
	is_object(rr)
	object.get(rr, "ReplaceKeyWith", "__pf_absent") != "__pf_absent"
	object.get(rr, "ReplaceKeyPrefixWith", "__pf_absent") != "__pf_absent"
}
