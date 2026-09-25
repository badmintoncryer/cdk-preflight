package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-template-placeholder-slot-match", "ERROR", name, path,
	sprintf("%v sits in the %v element of the scope; it is only valid in the matching one", [ph, w]),
	"Put ?principal in the principal element and ?resource in the resource element",
	"https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/policy-templates.html") if {
	some [name, path, s] in _pf_cedarlib_template
	some p in _pf_cedarlib_parts(s)
	w := _pf_cedarlib_word(p)
	some ph in _pf_cedarlib_slots(p)
	ph in {"?principal", "?resource"}
	ph != concat("", ["?", w])
}
