package cdk_preflight

import rego.v1

_pf_elblmm_fix := "Use off, passthrough or verify"

_pf_elblmm_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_MutualAuthenticationAttributes.html"

violation contains make_diag_full("pf-elbv2-listener-mtls-mode-values", "ERROR", name,
	"Properties.MutualAuthentication.Mode",
	sprintf("'%s' is not a mutual authentication mode; the accepted values are off, passthrough and verify", [mode]),
	_pf_elblmm_fix, _pf_elblmm_url) if {	some name in _pf_elb_listeners
	ma := resolve(name, "Properties.MutualAuthentication")
	is_object(ma)
	mode := object.get(ma, "Mode", "off")
	is_string(mode)
	not mode in {"off", "passthrough", "verify"}
}
