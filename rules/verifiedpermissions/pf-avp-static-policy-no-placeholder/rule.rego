package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-static-policy-no-placeholder", "ERROR", name, path,
	sprintf("static policy uses the template placeholder %v; placeholders only work in a PolicyTemplate", [ph]),
	"Move the statement to an AWS::VerifiedPermissions::PolicyTemplate, or write a concrete entity UID",
	"https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/policy-templates.html") if {
	some [name, path, s] in _pf_cedarlib_static
	some ph in _pf_cedarlib_slots(_pf_cedarlib_code(s))
}
