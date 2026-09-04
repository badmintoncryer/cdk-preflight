package cdk_preflight

import rego.v1

_pf_elbname_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

_pf_elbname_bad contains [name, n, why] if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::LoadBalancer")
	n := resolve(name, "Properties.Name")
	is_string(n)
	startswith(n, "internal-")
	why := "cannot begin with 'internal-'"
}

_pf_elbname_bad contains [name, n, why] if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::LoadBalancer")
	n := resolve(name, "Properties.Name")
	is_string(n)
	endswith(n, "-")
	why := "cannot end with a hyphen(-)"
}

_pf_elbname_bad contains [name, n, why] if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::LoadBalancer")
	n := resolve(name, "Properties.Name")
	is_string(n)
	startswith(n, "-")
	why := "cannot begin with a hyphen(-)"
}

_pf_elbname_bad contains [name, n, why] if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::LoadBalancer")
	n := resolve(name, "Properties.Name")
	is_string(n)
	count(n) > 32
	why := "cannot be longer than '32' characters"
}

_pf_elbname_bad contains [name, n, why] if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::LoadBalancer")
	n := resolve(name, "Properties.Name")
	is_string(n)
	not regex.match(`^[A-Za-z0-9-]*$`, n)
	why := "can only contain characters that are alphanumeric characters and hyphens(-)"
}

violation contains make_diag_full("pf-elbv2-lb-name", "ERROR", name,
	"Properties.Name",
	sprintf("The load balancer name '%s' %s; ELB rejects the create call", [n, why]),
	"Rename the load balancer to at most 32 alphanumeric or hyphen characters, without a leading/trailing hyphen or the reserved internal- prefix",
	_pf_elbname_url) if {
	some [name, n, why] in _pf_elbname_bad
}
