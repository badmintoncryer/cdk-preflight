package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-apigw-regional-certificate-property", "ERROR", name,
	"Properties.CertificateArn",
	"A REGIONAL domain name carries CertificateArn; the domain name create fails with \"Cannot import certificates for EDGE while REGIONAL is active.\"",
	"Put the certificate in RegionalCertificateArn, or switch EndpointConfiguration.Types to EDGE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-domainname.html") if {
	some name in resources_of_type("AWS::ApiGateway::DomainName")
	some t in flatten_list(name, "Properties.EndpointConfiguration.Types")
	t.value == "REGIONAL"
	is_string(resolve(name, "Properties.CertificateArn"))
}
