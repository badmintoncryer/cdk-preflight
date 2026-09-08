package cdk_preflight

import rego.v1

# The certificate property is chosen by endpoint type: EDGE reads CertificateArn
# (an us-east-1 certificate), REGIONAL reads RegionalCertificateArn.
violation contains make_diag_full("pf-apigw-edge-certificate-property", "ERROR", name,
	"Properties.RegionalCertificateArn",
	"An EDGE domain name carries RegionalCertificateArn; the domain name create fails with \"Cannot import certificates for REGIONAL while EDGE is active.\"",
	"Put the us-east-1 certificate in CertificateArn, or switch EndpointConfiguration.Types to REGIONAL",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-domainname.html") if {
	some name in resources_of_type("AWS::ApiGateway::DomainName")
	some t in flatten_list(name, "Properties.EndpointConfiguration.Types")
	t.value == "EDGE"
	is_string(resolve(name, "Properties.RegionalCertificateArn"))
}
