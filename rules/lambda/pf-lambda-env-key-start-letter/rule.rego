package cdk_preflight

import rego.v1

_pf_lekl_fix := "Rename the variable to start with a letter and use only letters, digits and underscores"

_pf_lekl_url := "https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html"

violation contains make_diag_full("pf-lambda-env-key-start-letter", "ERROR", name,
	sprintf("Properties.Environment.Variables.%v", [k]),
	sprintf("environment variable '%v'; Lambda accepts names that start with a letter and continue with letters, digits and underscores", [k]),
	_pf_lekl_fix, _pf_lekl_url) if {
	some name in _pf_lam_fn
	props := _pf_lam_props(name)
	vars := _pf_lam_obj(_pf_lam_obj(props, "Environment"), "Variables")
	some k, _ in vars
	not regex.match(`^[a-zA-Z][a-zA-Z0-9_]*$`, k)
}
