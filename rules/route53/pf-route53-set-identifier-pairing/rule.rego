package cdk_preflight

import rego.v1

_pf_r53_sidp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53-recordset.html"

_pf_r53_sidp_props := ["Weight", "Region", "Failover", "GeoLocation", "CidrRoutingConfig"]

_pf_r53_sidp_has_policy(name) if {
	some p in _pf_r53_sidp_props
	resolve(name, sprintf("Properties.%s", [p])) != null
}

_pf_r53_sidp_has_policy(name) if {
	resolve(name, "Properties.MultiValueAnswer") == true
}

violation contains make_diag_full("pf-route53-set-identifier-pairing", "ERROR", name,
	"Properties.SetIdentifier",
	"A routing policy is configured but SetIdentifier is missing; the ChangeResourceRecordSets call fails with \"Missing field 'SetIdentifier'\"",
	"Add a SetIdentifier that is unique among the record sets sharing this Name and Type",
	_pf_r53_sidp_url) if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	_pf_r53_sidp_has_policy(name)
	not is_string(resolve(name, "Properties.SetIdentifier"))
}

violation contains make_diag_full("pf-route53-set-identifier-pairing", "ERROR", name,
	"Properties.SetIdentifier",
	"SetIdentifier is specified but no routing policy is; the service expects exactly one of Weight, Region, Failover, GeoLocation, MultiValueAnswer, or CidrRoutingConfig and finds none",
	"Remove SetIdentifier from this simple record set, or add the routing policy it was meant for",
	_pf_r53_sidp_url) if {
	some name in resources_of_type("AWS::Route53::RecordSet")
	is_string(resolve(name, "Properties.SetIdentifier"))
	not _pf_r53_sidp_has_policy(name)
}
