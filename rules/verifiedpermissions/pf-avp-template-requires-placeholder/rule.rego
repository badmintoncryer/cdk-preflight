package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-template-requires-placeholder", "ERROR", name, path,
	sprintf("policy template has no ?principal or ?resource: %v", [trim_space(c)]),
	"Put ?principal in the principal element or ?resource in the resource element, or make it a static Policy",
	"https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/policy-templates.html") if {
	some [name, path, s] in _pf_cedarlib_template
	c := _pf_cedarlib_code(s)
	count(regex.find_n(`\?(principal|resource)($|[^A-Za-z_0-9])`, c, -1)) == 0
}
