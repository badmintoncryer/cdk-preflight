package cdk_preflight

import rego.v1

# The schema allows up to 100 Targets on every type, but an LAMBDA target group
# holds one function. The CloudFormation handler rejects a second one itself
# ("TargetGroup of type LAMBDA can't have more than 1 Target registered"); the
# RegisterTargets API says "Maximum of 1 targets are supported per request".
violation contains make_diag_full("pf-vpclattice-tg-lambda-single-target", "ERROR", name,
	"Properties.Targets",
	sprintf("An LAMBDA target group takes one target but %d are listed; the create fails with \"TargetGroup of type LAMBDA can't have more than 1 Target registered\"", [count(l)]),
	"Keep one function per target group; create another target group for each additional function",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/lambda-functions.html") if {
	some name in _pf_vpcl_tgs_of("LAMBDA")
	_pf_countable_list(name, "Properties.Targets")
	l := flatten_list(name, "Properties.Targets")
	count(l) > 1
}
