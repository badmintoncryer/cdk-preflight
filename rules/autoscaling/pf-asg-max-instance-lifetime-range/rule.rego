package cdk_preflight

import rego.v1

_pf_asgmil_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

_pf_asgmil_bad(n) if {
	n > 0
	n < 86400
}

_pf_asgmil_bad(n) if n > 31536000

violation contains make_diag_full("pf-asg-max-instance-lifetime-range", "ERROR", name,
	"Properties.MaxInstanceLifetime",
	sprintf("MaxInstanceLifetime %v is neither 0 nor within 86400-31536000 seconds; the group create fails with \"maxInstanceLifetime must be between 86400 and 31536000 seconds (inclusive)\"", [n]),
	"Use 0 to switch replacement off, or a value from 86400 (one day) to 31536000 (one year)", _pf_asgmil_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	n := _pf_aslib_num(name, "Properties.MaxInstanceLifetime")
	_pf_asgmil_bad(n)
}
