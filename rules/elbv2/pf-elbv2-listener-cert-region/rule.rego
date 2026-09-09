package cdk_preflight

import rego.v1

_pf_elblcr_fix := "Import or request the certificate in the region the load balancer is deployed to"

_pf_elblcr_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-cert-region", "ERROR", name,
	sprintf("Properties.Certificates.%d.CertificateArn", [c.index]),
	sprintf("The certificate is in %s but the load balancer is deployed to %s; a listener certificate must be in the same region", [cr, _pf_elb_region]),
	_pf_elblcr_fix, _pf_elblcr_url) if {
	some name in _pf_elb_listeners
	some c in flatten_list(name, "Properties.Certificates")
	arn := _pf_elb_oget(c.value, "CertificateArn")
	_pf_elb_lit(arn)
	cr := _pf_elb_arn_region(arn)
	cr != _pf_elb_region
}
