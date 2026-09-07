package cdk_preflight

import rego.v1

_pf_leram_fix := "Use 60 or more, or -1 for the stream retention period"

_pf_leram_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"

violation contains make_diag_full("pf-lambda-esm-record-age-effective-min", "ERROR", name,
	"Properties.MaximumRecordAgeInSeconds",
	sprintf("MaximumRecordAgeInSeconds is %v; the accepted values are -1 (stream retention) or 60 and above", [n]),
	_pf_leram_fix, _pf_leram_url) if {
	some name in _pf_lam_esm
	n := to_number(_pf_lam_get(name, "MaximumRecordAgeInSeconds"))
	n != -1
	n < 60
}
