package cdk_preflight

import rego.v1

# The service enforces "Expected exactly one of [Weight, Region, Failover,
# GeoLocation, MultiValueAnswer, GeoProximityLocation, or CidrRoutingConfig]".
# GeoProximityLocation is not a CloudFormation property, so five remain here.
# MultiValueAnswer: false is treated as absent — only true selects the policy.
_pf_r53_polx_props := ["Weight", "Region", "Failover", "GeoLocation", "CidrRoutingConfig"]

_pf_r53_polx_present(name, prop) if {
	prop != "MultiValueAnswer"
	resolve(name, sprintf("Properties.%s", [prop])) != null
}

_pf_r53_polx_present(name, "MultiValueAnswer") if {
	resolve(name, "Properties.MultiValueAnswer") == true
}

_pf_r53_polx_policies(name) := ps if {
	ps := [p | some p in array.concat(_pf_r53_polx_props, ["MultiValueAnswer"]); _pf_r53_polx_present(name, p)]
}

violation contains make_diag_full("pf-route53-routing-policy-exclusive", "ERROR", name,
	"Properties",
	sprintf("A record set can use only one routing policy, but %v are all specified", [ps]),
	"Keep exactly one of Weight, Region, Failover, GeoLocation, MultiValueAnswer, or CidrRoutingConfig and split the rest into separate record sets",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html") if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	ps := _pf_r53_polx_policies(name)
	count(ps) > 1
}
