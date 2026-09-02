package cdk_preflight

import rego.v1

_pf_cf_geo_path := "Properties.DistributionConfig.Restrictions.GeoRestriction"

_pf_cf_geo_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-cloudfront-distribution-georestriction.html"

_pf_cf_geo_locations(name) := count([1 |
	some _ in flatten_list(name, sprintf("%s.Locations", [_pf_cf_geo_path]))
])

violation contains make_diag_full("pf-cloudfront-geo-restriction-locations", "ERROR", name,
	sprintf("%s.Locations", [_pf_cf_geo_path]),
	sprintf("RestrictionType '%s' requires at least one country code in Locations", [kind]),
	"List the ISO 3166-1 alpha-2 country codes in Locations, or set RestrictionType to none",
	_pf_cf_geo_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	kind := resolve(name, sprintf("%s.RestrictionType", [_pf_cf_geo_path]))
	kind in {"whitelist", "blacklist"}
	_pf_cf_geo_locations(name) == 0
}

violation contains make_diag_full("pf-cloudfront-geo-restriction-locations", "ERROR", name,
	sprintf("%s.Locations", [_pf_cf_geo_path]),
	"RestrictionType 'none' must not be combined with Locations",
	"Remove Locations, or switch RestrictionType to whitelist or blacklist",
	_pf_cf_geo_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	resolve(name, sprintf("%s.RestrictionType", [_pf_cf_geo_path])) == "none"
	_pf_cf_geo_locations(name) > 0
}
