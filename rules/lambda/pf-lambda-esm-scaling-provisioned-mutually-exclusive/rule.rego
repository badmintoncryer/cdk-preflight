package cdk_preflight

import rego.v1

_pf_lekse_fix := "Keep either ScalingConfig (on-demand) or ProvisionedPollerConfig (provisioned mode)"

_pf_lekse_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-lambda-eventsourcemapping.html"

violation contains make_diag_full("pf-lambda-esm-scaling-provisioned-mutually-exclusive", "ERROR", name,
	"Properties.ProvisionedPollerConfig",
	"the mapping sets both ScalingConfig and ProvisionedPollerConfig; on-demand scaling and provisioned mode are alternatives, not a combination",
	_pf_lekse_fix, _pf_lekse_url) if {
	some name in _pf_lam_esm
	_pf_lam_has(name, "ScalingConfig")
	_pf_lam_has(name, "ProvisionedPollerConfig")
}
