package cdk_preflight

import rego.v1

_pf_elblcrg_fix := "Use a certificate issued in the region this stack deploys to"

_pf_elblcrg_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-listenercertificate.html"

violation contains make_diag_full("pf-elbv2-listener-certificate-region", "ERROR", name,
	sprintf("Properties.Certificates.%d.CertificateArn", [c.index]),
	sprintf("The certificate is in %s but this stack deploys to %s; a listener can only serve certificates from its own region", [r, _pf_elb_region]),
	_pf_elblcrg_fix, _pf_elblcrg_url) if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::ListenerCertificate")
	some c in flatten_list(name, "Properties.Certificates")
	r := _pf_elb_arn_region(object.get(c.value, "CertificateArn", null))
	r != _pf_elb_region
}
