package cdk_preflight

import rego.v1

_pf_leodl_fix := "Use a shorter destination ARN"

_pf_leodl_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventsourcemapping-onfailure.html"

violation contains make_diag_full("pf-lambda-esm-on-failure-destination-api-max-length", "ERROR", name,
	"Properties.DestinationConfig.OnFailure.Destination",
	sprintf("the destination ARN is %v characters; the API caps it at 350", [count(d)]),
	_pf_leodl_fix, _pf_leodl_url) if {
	some name in _pf_lam_esm
	d := resolve(name, "Properties.DestinationConfig.OnFailure.Destination")
	_pf_lam_lit(d)
	count(d) > 350
}
