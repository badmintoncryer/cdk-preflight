package cdk_preflight

import rego.v1

_pf_cf_staging_requires_no_aliases_fix := "Remove Aliases from the staging distribution"

_pf_cf_staging_requires_no_aliases_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-staging-requires-no-aliases", "ERROR", name, "Properties.DistributionConfig",
	"a staging distribution cannot declare alternate domain names",
	_pf_cf_staging_requires_no_aliases_fix, _pf_cf_staging_requires_no_aliases_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	cfg := _pf_cflib_config(name)
	object.get(cfg, "Staging", false) == true
	count(object.get(cfg, "Aliases", [])) > 0
}
