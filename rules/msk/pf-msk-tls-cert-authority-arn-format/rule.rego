package cdk_preflight

import rego.v1

# The list is typed Array of String with no pattern, so an ACM certificate ARN - the neighbouring
# service, and the one an author reaches for first - passes every earlier layer. The create fails
# with "One or more of the certificate authority ARNs provided in the request are invalid. ...
# InvalidParameter: clientAuthentication".
violation contains make_diag_full("pf-msk-tls-cert-authority-arn-format", "ERROR", name,
	"Properties.ClientAuthentication.Tls.CertificateAuthorityArnList",
	sprintf("'%s' is a %s ARN, not an AWS Private CA one; the create fails with \"One or more of the certificate authority ARNs provided in the request are invalid\"", [arn, svc]),
	"List AWS Private CA authorities (arn:<partition>:acm-pca:<region>:<account>:certificate-authority/<id>)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-tls.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	some item in flatten_list(name, "Properties.ClientAuthentication.Tls.CertificateAuthorityArnList")
	arn := item.value
	is_string(arn)
	startswith(arn, "arn:")
	parts := split(arn, ":")
	count(parts) > 5
	svc := parts[2]
	svc != "acm-pca"
}
