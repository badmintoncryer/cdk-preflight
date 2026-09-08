package cdk_preflight

import rego.v1

# SecurityPolicy defaults to TLS_1_0, so omitting it is a violation too - hence
# the positive helper plus a negation (AGENTS.md).
_pf_apgmtsp_tls12(name) if resolve(name, "Properties.SecurityPolicy") == "TLS_1_2"

violation contains make_diag_full("pf-apigw-mutual-tls-security-policy", "ERROR", name,
	"Properties.SecurityPolicy",
	"MutualTlsAuthentication is set but SecurityPolicy is not TLS_1_2 (the default is TLS_1_0); the domain name create fails with \"Mutual TLS authentication is only supported with TLS 1.2.\"",
	"Set SecurityPolicy: TLS_1_2 on the domain name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-domainname.html") if {
	some name in resources_of_type("AWS::ApiGateway::DomainName")
	is_object(resolve(name, "Properties.MutualTlsAuthentication"))
	not _pf_apgmtsp_tls12(name)
}
