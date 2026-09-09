package cdk_preflight

import rego.v1

_pf_elbtsr_fix := "Add RevocationContents pointing at the CRL in S3"

_pf_elbtsr_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-truststorerevocation.html"

violation contains make_diag_full("pf-elbv2-truststore-revocation-content-required", "ERROR", name,
	"Properties.RevocationContents",
	"The revocation has no RevocationContents, so there is nothing to add to the trust store",
	_pf_elbtsr_fix, _pf_elbtsr_url) if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::TrustStoreRevocation")
	_pf_elb_absent(name, "RevocationContents")
}
