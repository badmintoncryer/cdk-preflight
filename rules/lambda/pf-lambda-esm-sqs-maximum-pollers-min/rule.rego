package cdk_preflight

import rego.v1

_pf_lespm_fix := "Set MaximumPollers to 2 or more"

_pf_lespm_url := "https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html"

violation contains make_diag_full("pf-lambda-esm-sqs-maximum-pollers-min", "ERROR", name,
	"Properties.ProvisionedPollerConfig.MaximumPollers",
	sprintf("MaximumPollers is %v; provisioned mode needs at least 2 pollers", [n]),
	_pf_lespm_fix, _pf_lespm_url) if {
	some name in _pf_lam_esm
	n := to_number(object.get(_pf_lam_obj(_pf_lam_props(name), "ProvisionedPollerConfig"), "MaximumPollers", 2))
	n < 2
}
