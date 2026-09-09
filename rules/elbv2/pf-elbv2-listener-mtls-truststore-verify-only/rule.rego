package cdk_preflight

import rego.v1

_pf_elblmtv_fix := "Drop TrustStoreArn, or set Mode to verify"

_pf_elblmtv_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_MutualAuthenticationAttributes.html"

violation contains make_diag_full("pf-elbv2-listener-mtls-truststore-verify-only", "ERROR", name,
	"Properties.MutualAuthentication.TrustStoreArn",
	sprintf("TrustStoreArn is set with Mode '%s'; a trust store is only used when the listener verifies client certificates", [mode]),
	_pf_elblmtv_fix, _pf_elblmtv_url) if {	some name in _pf_elb_listeners
	ma := resolve(name, "Properties.MutualAuthentication")
	is_object(ma)
	_pf_elb_ohas(ma, "TrustStoreArn")
	mode := object.get(ma, "Mode", "off")
	mode != "verify"
}
