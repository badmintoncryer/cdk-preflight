package cdk_preflight

import rego.v1

_pf_cf_trusted_signers_account_format_fix := "Use \"self\" or a 12-digit AWS account id"

_pf_cf_trusted_signers_account_format_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-cachebehavior.html"

violation contains make_diag_full("pf-cloudfront-trusted-signers-account-format", "ERROR", name, b.path,
	sprintf("TrustedSigners entry %v is neither \"self\" nor a 12-digit account id", [s]),
	_pf_cf_trusted_signers_account_format_fix, _pf_cf_trusted_signers_account_format_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cflib_behaviors(name)
	sg := object.get(b.value, "TrustedSigners", null)
	is_array(sg)
	some s in sg
	is_string(s)
	s != "self"
	not regex.match("^[0-9]{12}$", s)
}
