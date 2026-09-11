package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53profiles-profileresourceassociation-priority-range", "ERROR", name,
	"Properties.ResourceProperties",
	sprintf("ResourceProperties asks for priority %d; Route 53 Profiles reserves 100 and below and 9900 and above", [v]),
	"Use a priority between 101 and 9899",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53profiles_AssociateResourceToProfile.html") if {
	some name in resources_of_type("AWS::Route53Profiles::ProfileResourceAssociation")
	v := _pf_r53r_rp_priority(_pf_r53r_str(_pf_r53r_props(name), "ResourceProperties"))
	_pf_r53r_outside_101_9899(v)
}
