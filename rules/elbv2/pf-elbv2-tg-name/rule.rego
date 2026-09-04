package cdk_preflight

import rego.v1

_pf_tgname_bad(n) := "cannot be longer than 32 characters" if count(n) > 32

_pf_tgname_bad(n) := "may use only alphanumerics and hyphens, and cannot start or end with a hyphen" if {
	count(n) <= 32
	not regex.match(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$`, n)
}

violation contains make_diag_full("pf-elbv2-tg-name", "ERROR", name,
	"Properties.Name",
	sprintf("The target group name '%s' %s; ELB rejects the create call", [n, why]),
	"Rename the target group to at most 32 alphanumeric or hyphen characters, not starting or ending with a hyphen",
	"https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html") if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::TargetGroup")
	n := resolve(name, "Properties.Name")
	is_string(n)
	why := _pf_tgname_bad(n)
}
