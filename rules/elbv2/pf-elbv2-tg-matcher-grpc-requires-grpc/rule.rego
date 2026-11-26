package cdk_preflight

import rego.v1

_pf_elbtmgr_fix := "Set ProtocolVersion to GRPC, or match on Matcher.HttpCode instead"

_pf_elbtmgr_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-matcher-grpc-requires-grpc", "ERROR", name,
	"Properties.Matcher.GrpcCode",
	sprintf("Matcher.GrpcCode is set with ProtocolVersion '%s'; gRPC status codes are only matched on a GRPC target group", [pv]),
	_pf_elbtmgr_fix, _pf_elbtmgr_url) if {
	some name in _pf_elb_tgs
	pv := _pf_oval(_pf_elb_props(name), "ProtocolVersion")
	pv != "GRPC"
	is_string(resolve(name, "Properties.Matcher.GrpcCode"))
}
