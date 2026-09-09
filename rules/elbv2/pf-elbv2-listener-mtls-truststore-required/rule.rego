package cdk_preflight

import rego.v1

_pf_elblmt_fix := "Set MutualAuthentication.TrustStoreArn to the trust store holding the client CA bundle"

_pf_elblmt_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_MutualAuthenticationAttributes.html"

violation contains make_diag_full("pf-elbv2-listener-mtls-truststore-required", "ERROR", name,
	"Properties.MutualAuthentication.TrustStoreArn",
	"MutualAuthentication.Mode is 'verify' without a TrustStoreArn; there is no CA bundle to verify client certificates against",
	_pf_elblmt_fix, _pf_elblmt_url) if {	some name in _pf_elb_listeners
	ma := resolve(name, "Properties.MutualAuthentication")
	is_object(ma)
	object.get(ma, "Mode", "off") == "verify"
	not _pf_elb_ohas(ma, "TrustStoreArn")
}
