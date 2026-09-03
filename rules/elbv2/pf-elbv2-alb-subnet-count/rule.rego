package cdk_preflight

import rego.v1

_pf_elbsc_alb(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "Type", "application") == "application"
}

violation contains make_diag_full("pf-elbv2-alb-subnet-count", "ERROR", name,
	"Properties.Subnets",
	sprintf("The application load balancer lists %v subnet(s); ELB requires at least two in different AZs (\"At least two subnets in two different Availability Zones must be specified\")", [count(subs)]),
	"List two or more subnets from different Availability Zones",
	"https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html") if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::LoadBalancer")
	_pf_elbsc_alb(name)
	props := input.resources[name].properties
	is_object(props)
	subs := object.get(props, "Subnets", "__pf_absent")
	is_array(subs)
	count(subs) < 2
}
