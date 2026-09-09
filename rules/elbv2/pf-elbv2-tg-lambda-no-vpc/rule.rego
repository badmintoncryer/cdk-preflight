package cdk_preflight

import rego.v1

_pf_elbtlv_fix := "Drop VpcId; a Lambda target is reached through the function ARN"

_pf_elbtlv_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-lambda-no-vpc", "ERROR", name,
	"Properties.VpcId",
	"VpcId is set on a lambda target group; CreateTargetGroup rejects a VPC for target type 'lambda'",
	_pf_elbtlv_fix, _pf_elbtlv_url) if {
	some name in _pf_elb_tgs
	_pf_elb_tgtype(name) == "lambda"
	_pf_elb_has(name, "VpcId")
}
