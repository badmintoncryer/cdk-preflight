package cdk_preflight

import rego.v1

_pf_elblmav_fix := "Drop AdvertiseTrustStoreCaNames, or set Mode to verify"

_pf_elblmav_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_MutualAuthenticationAttributes.html"

violation contains make_diag_full("pf-elbv2-listener-mtls-advertise-verify-only", "ERROR", name,
	"Properties.MutualAuthentication.AdvertiseTrustStoreCaNames",
	sprintf("AdvertiseTrustStoreCaNames is set with Mode '%s'; the CA names come from the trust store used in verify mode", [mode]),
	_pf_elblmav_fix, _pf_elblmav_url) if {	some name in _pf_elb_listeners
	ma := resolve(name, "Properties.MutualAuthentication")
	is_object(ma)
	_pf_elb_ohas(ma, "AdvertiseTrustStoreCaNames")
	mode := object.get(ma, "Mode", "off")
	mode != "verify"
}
