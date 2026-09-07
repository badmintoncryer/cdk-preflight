package cdk_preflight

import rego.v1

_pf_lesnm_fix := "Set MinimumPollers to 2 or more"

_pf_lesnm_url := "https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html"

violation contains make_diag_full("pf-lambda-esm-sqs-minimum-pollers-min", "ERROR", name,
	"Properties.ProvisionedPollerConfig.MinimumPollers",
	sprintf("MinimumPollers is %v; provisioned mode needs at least 2 pollers", [n]),
	_pf_lesnm_fix, _pf_lesnm_url) if {
	some name in _pf_lam_esm
	n := to_number(object.get(_pf_lam_obj(_pf_lam_props(name), "ProvisionedPollerConfig"), "MinimumPollers", 2))
	n < 2
}
