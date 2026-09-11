package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53profiles-profileassociation-one-per-vpc", "ERROR", name,
	"Properties.ResourceId",
	"another ProfileAssociation in this template attaches a second Profile to the same VPC",
	"Attach one Profile per VPC",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53profiles_AssociateProfile.html") if {
	some name in resources_of_type("AWS::Route53Profiles::ProfileAssociation")
	k := _pf_r53r_key(_pf_r53r_props(name), "ResourceId")
	dup := [1 |
		some o in resources_of_type("AWS::Route53Profiles::ProfileAssociation")
		_pf_r53r_key(_pf_r53r_props(o), "ResourceId") == k
	]
	count(dup) > 1
}
