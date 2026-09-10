package cdk_preflight

import rego.v1

_pf_r53_geox_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53-recordset-geolocation.html"

_pf_r53_geox_has(geo, k) if {
	is_string(object.get(geo, k, null))
}

# The registry schema expresses this as a oneOf, which the server-side
# pre-deploy validation enforces ("2 subschemas matched instead of one") but
# the bundled engine does not evaluate — hence upstream: pending-engine.
violation contains make_diag_full("pf-route53-geolocation-exclusive", "ERROR", name,
	"Properties.GeoLocation",
	"GeoLocation cannot specify both ContinentCode and CountryCode; CloudFormation rejects the record set before provisioning",
	"Keep either the ContinentCode or the CountryCode (add SubdivisionCode only next to CountryCode US)",
	_pf_r53_geox_url) if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	geo := resolve(name, "Properties.GeoLocation")
	is_object(geo)
	_pf_r53_geox_has(geo, "ContinentCode")
	_pf_r53_geox_has(geo, "CountryCode")
}

# SubdivisionCode only ever qualifies a CountryCode, so pairing it with a
# ContinentCode is the same mistake seen from the other side: Route 53 answers
# "Cannot find location: ' continent = NA subdivision = CA'" (2026-09-08).
violation contains make_diag_full("pf-route53-geolocation-exclusive", "ERROR", name,
	"Properties.GeoLocation",
	"GeoLocation cannot specify both ContinentCode and SubdivisionCode; a subdivision only qualifies CountryCode US",
	"Route on the continent alone, or replace ContinentCode with CountryCode: US next to the SubdivisionCode",
	_pf_r53_geox_url) if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	geo := resolve(name, "Properties.GeoLocation")
	is_object(geo)
	_pf_r53_geox_has(geo, "ContinentCode")
	_pf_r53_geox_has(geo, "SubdivisionCode")
}
