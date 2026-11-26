package cdk_preflight

import rego.v1

_pf_r53_sidp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html"

# GeoProximityLocation became a CloudFormation property after this rule was
# written; without it here a geoproximity record set reads as "SetIdentifier
# with no routing policy" and the rule false-positives (measured 2026-09-10).
_pf_r53_sidp_props := ["Weight", "Region", "Failover", "GeoLocation", "GeoProximityLocation", "CidrRoutingConfig"]

# Presence is read on the raw properties: a value built with Fn::Join or Fn::Sub does not
# resolve(), and reading that as "absent" fired on a SetIdentifier that was there.
_pf_r53_sidp_present(name, p) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, p, null) != null
}

_pf_r53_sidp_has_policy(name) if {
	some p in _pf_r53_sidp_props
	_pf_r53_sidp_present(name, p)
}

_pf_r53_sidp_has_policy(name) if {
	_pf_r53_sidp_present(name, "MultiValueAnswer")
	not resolve(name, "Properties.MultiValueAnswer") in {false, "false"}
}

violation contains make_diag_full("pf-route53-set-identifier-pairing", "ERROR", name,
	"Properties.SetIdentifier",
	"A routing policy is configured but SetIdentifier is missing; the ChangeResourceRecordSets call fails with \"Missing field 'SetIdentifier'\"",
	"Add a SetIdentifier that is unique among the record sets sharing this Name and Type",
	_pf_r53_sidp_url) if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	_pf_r53_sidp_has_policy(name)
	not _pf_r53_sidp_present(name, "SetIdentifier")
}

violation contains make_diag_full("pf-route53-set-identifier-pairing", "ERROR", name,
	"Properties.SetIdentifier",
	"SetIdentifier is specified but no routing policy is; the service expects exactly one of Weight, Region, Failover, GeoLocation, GeoProximityLocation, MultiValueAnswer, or CidrRoutingConfig and finds none",
	"Remove SetIdentifier from this simple record set, or add the routing policy it was meant for",
	_pf_r53_sidp_url) if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	_pf_r53_sidp_present(name, "SetIdentifier")
	not _pf_r53_sidp_has_policy(name)
}
