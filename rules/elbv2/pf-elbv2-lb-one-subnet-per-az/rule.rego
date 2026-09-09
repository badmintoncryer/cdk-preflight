package cdk_preflight

import rego.v1

_pf_elbaz_fix := "Give the load balancer one subnet per availability zone"

_pf_elbaz_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

_pf_elbaz_az(v) := az if {
	sub := _pf_elb_ref(v)
	sub in resources_of_type("AWS::EC2::Subnet")
	az := resolve(sub, "Properties.AvailabilityZone")
	is_string(az)
}

_pf_elbaz_azs(name) := [az |
	some s in flatten_list(name, "Properties.Subnets")
	az := _pf_elbaz_az(s.value)
]

violation contains make_diag_full("pf-elbv2-lb-one-subnet-per-az", "ERROR", name,
	"Properties.Subnets",
	sprintf("Two subnets of the load balancer sit in availability zone %s; CreateLoadBalancer fails with \"A load balancer cannot be attached to multiple subnets in the same Availability Zone.\"", [az]),
	_pf_elbaz_fix, _pf_elbaz_url) if {
	some name in _pf_elb_lbs
	azs := _pf_elbaz_azs(name)
	some az in azs
	count([x | some x in azs; x == az]) > 1
}
