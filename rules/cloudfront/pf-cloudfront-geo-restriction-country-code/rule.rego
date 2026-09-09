package cdk_preflight

import rego.v1

_pf_cf_geo_restriction_country_code_fix := "Use the ISO 3166-1 alpha-2 code (JP, not JPN)"

_pf_cf_geo_restriction_country_code_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-cloudfront-distribution-distributionconfig.html"

violation contains make_diag_full("pf-cloudfront-geo-restriction-country-code", "ERROR", name, "Properties.DistributionConfig.Restrictions.GeoRestriction",
	sprintf("%v is not an ISO 3166-1 alpha-2 country code", [c]),
	_pf_cf_geo_restriction_country_code_fix, _pf_cf_geo_restriction_country_code_url) if {
	some name in resources_of_type("AWS::CloudFront::Distribution")
	rs := object.get(_pf_cflib_config(name), "Restrictions", null)
	is_object(rs)
	gr := object.get(rs, "GeoRestriction", null)
	is_object(gr)
	some c in object.get(gr, "Locations", [])
	is_string(c)
	not regex.match("^[A-Z]{2}$", c)
}
