package cdk_preflight

import rego.v1

_pf_elbtvr_fix := "Set VpcId to the VPC the targets live in"

_pf_elbtvr_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-vpc-required-non-lambda", "ERROR", name,
	"Properties.VpcId",
	sprintf("TargetType is '%s' but VpcId is missing; only a lambda target group may omit it", [t]),
	_pf_elbtvr_fix, _pf_elbtvr_url) if {
	some name in _pf_elb_tgs
	t := _pf_elb_tgtype(name)
	t != "lambda"
	_pf_elb_absent(name, "VpcId")
}
