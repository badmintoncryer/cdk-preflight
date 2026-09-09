package cdk_preflight

import rego.v1

_pf_cf_geo_restriction_locations_exclusive_fix := "Drop Locations, or switch to whitelist / blacklist"

_pf_cf_geo_restriction_locations_exclusive_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-geo-restriction-locations-exclusive", "ERROR", name, "Properties.DistributionConfig.Restrictions.GeoRestriction",
	"RestrictionType none cannot be combined with Locations",
	_pf_cf_geo_restriction_locations_exclusive_fix, _pf_cf_geo_restriction_locations_exclusive_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	rs := object.get(_pf_cflib_config(name), "Restrictions", null)
	is_object(rs)
	gr := object.get(rs, "GeoRestriction", null)
	is_object(gr)
	object.get(gr, "RestrictionType", null) == "none"
	count(object.get(gr, "Locations", [])) > 0
}
