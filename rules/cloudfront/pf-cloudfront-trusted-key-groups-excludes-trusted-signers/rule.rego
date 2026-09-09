package cdk_preflight

import rego.v1

_pf_cf_trusted_key_groups_excludes_trusted_signers_fix := "Use TrustedKeyGroups alone; TrustedSigners is the deprecated form"

_pf_cf_trusted_key_groups_excludes_trusted_signers_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-cachebehavior.html"

violation contains make_diag_full("pf-cloudfront-trusted-key-groups-excludes-trusted-signers", "ERROR", name, b.path,
	sprintf("a cache behavior cannot set both TrustedKeyGroups (%v) and TrustedSigners (%v)", [kg, sg]),
	_pf_cf_trusted_key_groups_excludes_trusted_signers_fix, _pf_cf_trusted_key_groups_excludes_trusted_signers_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	some b in _pf_cflib_behaviors(name)
	kg := object.get(b.value, "TrustedKeyGroups", [])
	is_array(kg)
	count(kg) > 0
	sg := object.get(b.value, "TrustedSigners", [])
	is_array(sg)
	count(sg) > 0
}
