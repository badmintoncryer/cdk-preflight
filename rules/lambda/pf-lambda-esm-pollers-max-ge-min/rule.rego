package cdk_preflight

import rego.v1

_pf_lepmm_fix := "Raise MaximumPollers to at least MinimumPollers"

_pf_lepmm_url := "https://docs.aws.amazon.com/lambda/latest/dg/kafka-scaling-modes.html"

violation contains make_diag_full("pf-lambda-esm-pollers-max-ge-min", "ERROR", name,
	"Properties.ProvisionedPollerConfig.MaximumPollers",
	sprintf("MaximumPollers %v is below MinimumPollers %v", [mx, mn]),
	_pf_lepmm_fix, _pf_lepmm_url) if {
	some name in _pf_lam_esm
	c := _pf_lam_ppc(name)
	mn := to_number(object.get(c, "MinimumPollers", 2))
	mx := to_number(object.get(c, "MaximumPollers", 2000))
	mx < mn
}
