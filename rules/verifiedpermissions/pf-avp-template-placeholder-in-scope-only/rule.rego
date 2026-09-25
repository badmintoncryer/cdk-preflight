package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-template-placeholder-in-scope-only", "ERROR", name, path,
	sprintf("%v appears in a when/unless clause; placeholders are only allowed in the scope", [ph]),
	"Move the placeholder into the principal or resource element of the scope",
	"https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/policy-templates.html") if {
	some [name, path, s] in _pf_cedarlib_template
	some ph in _pf_cedarlib_slots(_pf_cedarlib_body(s))
}
