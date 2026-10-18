package cdk_preflight

import rego.v1

# The schema allows up to 100 Targets on every type, but an ALB target group
# holds one load balancer. The CloudFormation handler rejects a second one itself
# ("TargetGroup of type ALB can't have more than 1 Target registered"); the
# RegisterTargets API says "Maximum of 1 targets are supported per request".
violation contains make_diag_full("pf-vpclattice-tg-alb-single-target", "ERROR", name,
	"Properties.Targets",
	sprintf("An ALB target group takes one target but %d are listed; the create fails with \"TargetGroup of type ALB can't have more than 1 Target registered\"", [count(l)]),
	"Keep one load balancer per target group; create another target group for each additional load balancer",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/target-groups.html") if {
	some name in _pf_vpcl_tgs_of("ALB")
	_pf_countable_list(name, "Properties.Targets")
	l := flatten_list(name, "Properties.Targets")
	count(l) > 1
}
