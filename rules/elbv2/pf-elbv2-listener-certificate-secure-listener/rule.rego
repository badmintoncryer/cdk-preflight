package cdk_preflight

import rego.v1

_pf_elblcsl_fix := "Attach the certificate to an HTTPS (ALB) or TLS (NLB) listener"

_pf_elblcsl_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html"

violation contains make_diag_full("pf-elbv2-listener-certificate-secure-listener", "ERROR", name,
	"Properties.ListenerArn",
	sprintf("The certificate is attached to a %s listener; only HTTPS and TLS listeners terminate TLS", [proto]),
	_pf_elblcsl_fix, _pf_elblcsl_url) if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::ListenerCertificate")
	l := resolve(name, "Properties.ListenerArn")
	l in _pf_elb_listeners
	proto := object.get(_pf_elb_props(l), "Protocol", "GENEVE")
	not proto in _pf_elb_secure
}
