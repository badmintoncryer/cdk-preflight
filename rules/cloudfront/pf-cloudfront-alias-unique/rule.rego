package cdk_preflight

import rego.v1

_pf_cf_alias_unique_fix := "List each alternate domain name once"

_pf_cf_alias_unique_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-alias-unique", "ERROR", name, "Properties.DistributionConfig",
	sprintf("alias %v is listed more than once", [k]),
	_pf_cf_alias_unique_fix, _pf_cf_alias_unique_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	cfg := _pf_cflib_config(name)
	al := object.get(cfg, "Aliases", null)
	is_array(al)
	some k in al
	is_string(k)
	count([x | some x in al; x == k]) > 1
}
