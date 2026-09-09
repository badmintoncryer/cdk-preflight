package cdk_preflight

import rego.v1

_pf_elbtmgc_fix := "Keep Matcher.GrpcCode inside 0-99"

_pf_elbtmgc_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-matcher-grpc-range", "ERROR", name,
	"Properties.Matcher.GrpcCode",
	sprintf("Matcher.GrpcCode '%s' includes %v, outside the gRPC status code range 0-99", [code, n]),
	_pf_elbtmgc_fix, _pf_elbtmgc_url) if {
	some name in _pf_elb_tgs
	code := resolve(name, "Properties.Matcher.GrpcCode")
	is_string(code)
	some n in _pf_elb_codes(code)
	_pf_elb_outside(n, 0, 99)
}
