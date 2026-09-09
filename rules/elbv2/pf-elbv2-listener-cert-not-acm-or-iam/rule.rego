package cdk_preflight

import rego.v1

_pf_elblca_fix := "Point CertificateArn at an ACM certificate (acm) or a server certificate uploaded to IAM (iam)"

_pf_elblca_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-cert-not-acm-or-iam", "ERROR", name,
	sprintf("Properties.Certificates.%d.CertificateArn", [c.index]),
	sprintf("CertificateArn names the '%s' service; a listener certificate is an ACM or IAM certificate", [svc]),
	_pf_elblca_fix, _pf_elblca_url) if {
	some name in _pf_elb_listeners
	some c in flatten_list(name, "Properties.Certificates")
	arn := _pf_elb_oget(c.value, "CertificateArn")
	_pf_elb_lit(arn)
	svc := _pf_elb_arn_service(arn)
	not svc in {"acm", "iam"}
}
