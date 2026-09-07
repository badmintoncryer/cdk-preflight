package cdk_preflight

import rego.v1

_pf_s3wer_fix := "Give the redirect rule a HostName, Protocol, ReplaceKeyWith, ReplaceKeyPrefixWith or HttpRedirectCode"

_pf_s3wer_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-s3-bucket-routingrule.html"

violation contains make_diag_full("pf-s3-website-empty-redirect-rule", "ERROR", name,
	sprintf("Properties.WebsiteConfiguration.RoutingRules.%d.RedirectRule", [r.index]),
	"the redirect rule is empty; PutBucketWebsite requires at least one redirect element",
	_pf_s3wer_fix, _pf_s3wer_url) if {
	some name in resources_of_type("AWS::S3::Bucket")
	some r in flatten_list(name, "Properties.WebsiteConfiguration.RoutingRules")
	is_object(r.value)
	rr := object.get(r.value, "RedirectRule", "__pf_absent")
	is_object(rr)
	count(rr) == 0
}
