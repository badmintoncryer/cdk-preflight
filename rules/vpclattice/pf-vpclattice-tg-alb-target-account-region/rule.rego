package cdk_preflight

import rego.v1

# Lattice registers only an Application Load Balancer of its own account and
# region; RegisterTargets rejects any other ARN as "ALB [arn:...] ARN is
# invalid" (a missing load balancer of the same account and region is "not
# found" instead). data.cdk_preflight.deploy_region / deploy_account are defined
# only in enforce mode, otherwise this rule skips.
_pf_vpcltaa_bad(p) := sprintf("region '%s' (the stack deploys to '%s')", [p[3], r]) if {
	r := data.cdk_preflight.deploy_region
	is_string(r)
	p[3] != r
}

_pf_vpcltaa_bad(p) := sprintf("account '%s' (the stack deploys to '%s')", [p[4], a]) if {
	a := data.cdk_preflight.deploy_account
	is_string(a)
	p[4] != ""
	p[4] != a
}

violation contains make_diag_full("pf-vpclattice-tg-alb-target-account-region", "ERROR", name,
	sprintf("Properties.Targets.%d.Id", [t.index]),
	sprintf("The load balancer belongs to %s; RegisterTargets fails with \"ALB [...] ARN is invalid\"", [why]),
	"Register an Application Load Balancer of the deploy account and region",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/alb-target.html") if {
	some name in _pf_vpcl_tgs_of("ALB")
	some t in flatten_list(name, "Properties.Targets")
	p := _pf_vpcl_arn(_pf_vpcl_target_id(t))
	p[2] == "elasticloadbalancing"
	why := _pf_vpcltaa_bad(p)
}
