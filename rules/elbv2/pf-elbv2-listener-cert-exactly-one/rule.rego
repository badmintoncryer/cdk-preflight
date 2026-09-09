package cdk_preflight

import rego.v1

_pf_elblc1_fix := "Keep one certificate here and add the others as AWS::ElasticLoadBalancingV2::ListenerCertificate resources"

_pf_elblc1_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-cert-exactly-one", "ERROR", name,
	"Properties.Certificates",
	sprintf("The listener declares %d certificates; CreateListener takes exactly one default certificate", [n]),
	_pf_elblc1_fix, _pf_elblc1_url) if {
	some name in _pf_elb_listeners
	n := count(flatten_list(name, "Properties.Certificates"))
	n > 1
}
