package cdk_preflight

import rego.v1

_pf_elbtsb_fix := "Set CaCertificatesBundleS3Bucket and CaCertificatesBundleS3Key together"

_pf_elbtsb_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-elasticloadbalancingv2-truststore.html"

_pf_elbtsb_pairs := [["CaCertificatesBundleS3Key", "CaCertificatesBundleS3Bucket"], ["CaCertificatesBundleS3Bucket", "CaCertificatesBundleS3Key"]]

violation contains make_diag_full("pf-elbv2-truststore-bundle-key-requires-bucket", "ERROR", name,
	sprintf("Properties.%s", [pair[1]]),
	sprintf("'%s' is set without '%s'; the trust store needs the whole S3 location of the CA bundle", [pair[0], pair[1]]),
	_pf_elbtsb_fix, _pf_elbtsb_url) if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::TrustStore")
	some pair in _pf_elbtsb_pairs
	_pf_elb_has(name, pair[0])
	_pf_elb_absent(name, pair[1])
}
