package cdk_preflight

import rego.v1

_pf_llpp_fix := "Share with an organization instead of listing accounts one by one"

_pf_llpp_url := "https://docs.aws.amazon.com/lambda/latest/api/API_AddLayerVersionPermission.html"

violation contains make_diag_full("pf-lambda-layerperm-policy-size", "ERROR", name,
	"Properties.Principal",
	sprintf("%v permissions on one layer version; each is a statement in the same resource policy and the policy has a size cap", [n]),
	_pf_llpp_fix, _pf_llpp_url) if {
	some name in _pf_lam_layerperm
	target := resolve(name, "Properties.LayerVersionArn")
	n := count({p |
		some p in _pf_lam_layerperm
		resolve(p, "Properties.LayerVersionArn") == target
	})
	n > 20
}
