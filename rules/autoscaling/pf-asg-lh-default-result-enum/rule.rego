package cdk_preflight

import rego.v1

_pf_asglhdr_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutLifecycleHook.html"

violation contains make_diag_full("pf-asg-lh-default-result-enum", "ERROR", name,
	"Properties.DefaultResult",
	sprintf("DefaultResult '%s' is not a hook result; the hook create fails with \"'DefaultResult' must be one of: CONTINUE, ABANDON\"", [v]),
	"Use CONTINUE or ABANDON", _pf_asglhdr_url) if {
	some name in resources_of_type("AWS::AutoScaling::LifecycleHook")
	v := resolve(name, "Properties.DefaultResult")
	_pf_aslib_lit(v)
	not v in ["CONTINUE", "ABANDON"]
}
