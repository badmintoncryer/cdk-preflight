package cdk_preflight

import rego.v1

# The registry schema expresses this as a oneOf, which the server-side
# pre-deploy validation enforces ("2 subschemas matched instead of one") but
# the bundled engine does not evaluate — hence upstream: pending-engine.
violation contains make_diag_full("pf-route53-geolocation-exclusive", "ERROR", name,
	"Properties.GeoLocation",
	"GeoLocation cannot specify both ContinentCode and CountryCode; CloudFormation rejects the record set before provisioning",
	"Keep either the ContinentCode or the CountryCode (add SubdivisionCode only next to CountryCode US)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53-recordset-geolocation.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	geo := resolve(name, "Properties.GeoLocation")
	is_object(geo)
	is_string(object.get(geo, "ContinentCode", null))
	is_string(object.get(geo, "CountryCode", null))
}
