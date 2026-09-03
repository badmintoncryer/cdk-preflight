package cdk_preflight

import rego.v1

_pf_elbname_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

_pf_elbname_bad(n) := "cannot begin with 'internal-'" if startswith(n, "internal-")

_pf_elbname_bad(n) := "cannot end with a hyphen(-)" if endswith(n, "-")

violation contains make_diag_full("pf-elbv2-lb-name", "ERROR", name,
	"Properties.Name",
	sprintf("The load balancer name '%s' %s; ELB rejects the create call", [n, why]),
	"Pick a name without the reserved internal- prefix or a trailing hyphen",
	_pf_elbname_url) if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::LoadBalancer")
	n := resolve(name, "Properties.Name")
	is_string(n)
	why := _pf_elbname_bad(n)
}
