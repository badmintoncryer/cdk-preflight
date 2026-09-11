package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53profiles-profileresourceassociation-rulegroup-requires-properties", "ERROR", name,
	"Properties.ResourceProperties",
	"a DNS Firewall rule group is being associated without ResourceProperties; the priority is required",
	"Add ResourceProperties, for example {\"priority\": 101}",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53profiles_AssociateResourceToProfile.html") if {
	some name in resources_of_type("AWS::Route53Profiles::ProfileResourceAssociation")
	p := _pf_r53r_props(name)
	_pf_r53r_pra_kind(p) == "firewall-rule-group"
	not _pf_r53r_has(p, "ResourceProperties")
}
