package cdk_preflight

import rego.v1

_pf_llpo_fix := "Use Principal \"*\" with OrganizationId, or drop OrganizationId and name the account"

_pf_llpo_url := "https://docs.aws.amazon.com/lambda/latest/api/API_AddLayerVersionPermission.html"

violation contains make_diag_full("pf-lambda-layerperm-organization-id-needs-wildcard-principal", "ERROR", name,
	"Properties.OrganizationId",
	sprintf("OrganizationId with principal '%v'; the organization only narrows the wildcard principal and does nothing next to a named account", [p]),
	_pf_llpo_fix, _pf_llpo_url) if {
	some name in _pf_lam_layerperm
	_pf_lam_has_key(_pf_lam_props(name), "OrganizationId")
	p := resolve(name, "Properties.Principal")
	p != "*"
}
