package cdk_preflight

import rego.v1

_pf_asglhht_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutLifecycleHook.html"

_pf_asglhht_bad(n) if n < 30

_pf_asglhht_bad(n) if n > 7200

violation contains make_diag_full("pf-asg-lh-heartbeat-timeout-range", "ERROR", name,
	"Properties.HeartbeatTimeout",
	sprintf("HeartbeatTimeout %v is outside 30-7200; the hook create fails with \"HeartbeatTimeout must be between 30 and 7200 seconds\"", [n]),
	"Use a HeartbeatTimeout between 30 and 7200 seconds", _pf_asglhht_url) if {
	some name in resources_of_type("AWS::AutoScaling::LifecycleHook")
	n := _pf_aslib_num(name, "Properties.HeartbeatTimeout")
	_pf_asglhht_bad(n)
}
