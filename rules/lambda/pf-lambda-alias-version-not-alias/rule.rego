package cdk_preflight

import rego.v1

_pf_ladva_fix := "Set FunctionVersion to a version number or a Version resource, not another alias"

_pf_ladva_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-alias.html"

violation contains make_diag_full("pf-lambda-alias-version-not-alias", "ERROR", name,
	"Properties.FunctionVersion",
	"an alias whose FunctionVersion names another alias; aliases resolve to versions only and the create is rejected",
	_pf_ladva_fix, _pf_ladva_url) if {
	some name in _pf_lam_alias
	resolve(name, "Properties.FunctionVersion") in _pf_lam_alias
}
