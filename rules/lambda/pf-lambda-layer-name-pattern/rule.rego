package cdk_preflight

import rego.v1

_pf_llnp_fix := "Use a LayerName matching [a-zA-Z0-9-_]+"

_pf_llnp_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-layerversion.html"

violation contains make_diag_full("pf-lambda-layer-name-pattern", "ERROR", name,
	"Properties.LayerName",
	sprintf("layer name '%v'; the name becomes part of the layer ARN so it takes only letters, digits, dashes and underscores", [v]),
	_pf_llnp_fix, _pf_llnp_url) if {
	some name in _pf_lam_layer
	v := resolve(name, "Properties.LayerName")
	is_string(v)
	not regex.match(`^[a-zA-Z0-9_-]{1,140}$`, v)
}
