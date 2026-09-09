package cdk_preflight

import rego.v1

_pf_asgihh_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

_pf_asgihh_bad(n) if n < 30

_pf_asgihh_bad(n) if n > 7200

violation contains make_diag_full("pf-asg-lifecycle-hook-heartbeat-timeout-range", "ERROR", name,
	sprintf("Properties.LifecycleHookSpecificationList.%d.HeartbeatTimeout", [i]),
	sprintf("HeartbeatTimeout %v is outside 30-7200; the group create fails with \"HeartbeatTimeout must be between 30 and 7200 seconds\"", [n]),
	"Use a HeartbeatTimeout between 30 and 7200 seconds", _pf_asgihh_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some i, h in _pf_aslib_hooks(name)
	is_object(h)
	v := object.get(h, "HeartbeatTimeout", null)
	v != null
	not is_object(v)
	n := to_number(v)
	_pf_asgihh_bad(n)
}
