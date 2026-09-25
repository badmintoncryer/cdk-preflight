package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-template-no-action-placeholder", "ERROR", name, path,
	sprintf("policy template uses %v; Cedar has only ?principal and ?resource", [ph]),
	"Name the action concretely, e.g. action == MyApp::Action::\"view\"",
	"https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/policy-templates.html") if {
	some [name, path, s] in _pf_cedarlib_template
	some ph in _pf_cedarlib_slots(_pf_cedarlib_code(s))
	not ph in {"?principal", "?resource"}
}
