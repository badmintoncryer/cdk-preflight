package cdk_preflight

import rego.v1

_pf_asgwpps_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutWarmPool.html"

violation contains make_diag_full("pf-asg-wp-poolstate-enum", "ERROR", name,
	"Properties.PoolState",
	sprintf("PoolState '%s' is not a warm pool state; the warm pool create fails with \"Member must satisfy enum value set: [Stopped, Hibernated, Running]\"", [v]),
	"Use Stopped, Running or Hibernated", _pf_asgwpps_url) if {
	some name in resources_of_type("AWS::AutoScaling::WarmPool")
	v := resolve(name, "Properties.PoolState")
	_pf_aslib_lit(v)
	not v in ["Stopped", "Running", "Hibernated"]
}
