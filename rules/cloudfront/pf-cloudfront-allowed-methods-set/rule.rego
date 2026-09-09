package cdk_preflight

import rego.v1

_pf_cf_allowed_methods_set_fix := "Use [GET,HEAD], [GET,HEAD,OPTIONS] or all seven methods"

_pf_cf_allowed_methods_set_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-cachebehavior.html"

violation contains make_diag_full("pf-cloudfront-allowed-methods-set", "ERROR", name, b.path,
	sprintf("AllowedMethods %v is not one of the three sets CloudFront supports", [am]),
	_pf_cf_allowed_methods_set_fix, _pf_cf_allowed_methods_set_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cflib_behaviors(name)
	am := object.get(b.value, "AllowedMethods", null)
	is_array(am)
	ms := {m | some m in am}
	ms != {"GET", "HEAD"}
	ms != {"GET", "HEAD", "OPTIONS"}
	ms != {"GET", "HEAD", "OPTIONS", "PUT", "PATCH", "POST", "DELETE"}
}
