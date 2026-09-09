package cdk_preflight

import rego.v1

_pf_elblmie_fix := "Drop IgnoreClientCertificateExpiry, or set Mode to verify"

_pf_elblmie_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_MutualAuthenticationAttributes.html"

violation contains make_diag_full("pf-elbv2-listener-mtls-ignore-expiry-verify-only", "ERROR", name,
	"Properties.MutualAuthentication.IgnoreClientCertificateExpiry",
	sprintf("IgnoreClientCertificateExpiry is set with Mode '%s'; expiry is only checked when the listener verifies client certificates", [mode]),
	_pf_elblmie_fix, _pf_elblmie_url) if {	some name in _pf_elb_listeners
	ma := resolve(name, "Properties.MutualAuthentication")
	is_object(ma)
	_pf_elb_ohas(ma, "IgnoreClientCertificateExpiry")
	mode := object.get(ma, "Mode", "off")
	mode != "verify"
}
