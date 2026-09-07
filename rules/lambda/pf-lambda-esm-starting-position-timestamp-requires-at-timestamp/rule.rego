package cdk_preflight

import rego.v1

_pf_lesta_fix := "Set StartingPosition to AT_TIMESTAMP, or drop StartingPositionTimestamp"

_pf_lesta_url := "https://docs.aws.amazon.com/lambda/latest/dg/services-kinesis-parameters.html"

violation contains make_diag_full("pf-lambda-esm-starting-position-timestamp-requires-at-timestamp", "ERROR", name,
	"Properties.StartingPositionTimestamp",
	sprintf("StartingPositionTimestamp with StartingPosition '%v'; the timestamp is only read when the position is AT_TIMESTAMP", [p]),
	_pf_lesta_fix, _pf_lesta_url) if {
	some name in _pf_lam_esm
	_pf_lam_has(name, "StartingPositionTimestamp")
	p := resolve(name, "Properties.StartingPosition")
	is_string(p)
	p != "AT_TIMESTAMP"
}
