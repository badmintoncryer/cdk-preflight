package cdk_preflight

import rego.v1

_pf_cf_price_class_enum_fix := "Use PriceClass_100, PriceClass_200 or PriceClass_All"

_pf_cf_price_class_enum_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-price-class-enum", "ERROR", name, "Properties.DistributionConfig",
	sprintf("PriceClass %v is not a valid value", [pc]),
	_pf_cf_price_class_enum_fix, _pf_cf_price_class_enum_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	cfg := _pf_cflib_config(name)
	pc := object.get(cfg, "PriceClass", null)
	is_string(pc)
	not pc in {"PriceClass_100", "PriceClass_200", "PriceClass_All"}
}
