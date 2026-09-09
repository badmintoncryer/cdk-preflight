package cdk_preflight

import rego.v1

_pf_elblmtr_fix := "Create the trust store in the region the load balancer is deployed to"

_pf_elblmtr_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_MutualAuthenticationAttributes.html"

violation contains make_diag_full("pf-elbv2-listener-mtls-truststore-region", "ERROR", name,
	"Properties.MutualAuthentication.TrustStoreArn",
	sprintf("The trust store is in %s but the load balancer is deployed to %s; a trust store is a regional resource", [tr, _pf_elb_region]),
	_pf_elblmtr_fix, _pf_elblmtr_url) if {	some name in _pf_elb_listeners
	ma := resolve(name, "Properties.MutualAuthentication")
	is_object(ma)
	arn := _pf_elb_oget(ma, "TrustStoreArn")
	_pf_elb_lit(arn)
	tr := _pf_elb_arn_region(arn)
	tr != _pf_elb_region
}
