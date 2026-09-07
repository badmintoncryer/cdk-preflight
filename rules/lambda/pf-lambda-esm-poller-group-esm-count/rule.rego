package cdk_preflight

import rego.v1

_pf_lepgc_fix := "Split the mappings across more than one PollerGroupName"

_pf_lepgc_url := "https://docs.aws.amazon.com/lambda/latest/dg/msk-esm-parameters.html"

_pf_lepgc_names := {g |
	some name in _pf_lam_esm
	g := object.get(_pf_lam_ppc(name), "PollerGroupName", "")
	g != ""
}

_pf_lepgc_count(g) := count([name |
	some name in _pf_lam_esm
	object.get(_pf_lam_ppc(name), "PollerGroupName", "") == g
])

violation contains make_diag_full("pf-lambda-esm-poller-group-esm-count", "ERROR", "PollerGroupName",
	"Properties.ProvisionedPollerConfig.PollerGroupName",
	sprintf("poller group '%v' holds %v event source mappings; the group limit is 100", [g, n]),
	_pf_lepgc_fix, _pf_lepgc_url) if {
	some g in _pf_lepgc_names
	n := _pf_lepgc_count(g)
	n > 100
}
