package cdk_preflight

import rego.v1

_pf_ledfd_fix := "Use \"UpdateLookup\" or \"Default\" (the casing is fixed)"

_pf_ledfd_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventsourcemapping-documentdbeventsourceconfig.html"

violation contains make_diag_full("pf-lambda-esm-docdb-full-document-values", "ERROR", name,
	"Properties.DocumentDBEventSourceConfig.FullDocument",
	sprintf("FullDocument is '%v'; the accepted values are UpdateLookup and Default, and the casing is fixed", [v]),
	_pf_ledfd_fix, _pf_ledfd_url) if {
	some name in _pf_lam_esm
	v := resolve(name, "Properties.DocumentDBEventSourceConfig.FullDocument")
	is_string(v)
	not v in {"UpdateLookup", "Default"}
}
