package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_account is injected only in enforce mode with a
# concrete account; the rule skips otherwise.
violation contains make_diag_full("pf-opensearch-custom-endpoint-cert-account", "ERROR", name,
	"Properties.DomainEndpointOptions.CustomEndpointCertificateArn",
	sprintf("the certificate is in account %v but the stack deploys to %v; CreateDomain answers \"Cross-account certificate references are not allowed.\"", [a, acct]),
	"Import or issue the certificate in the account the domain deploys into",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/customendpoint.html") if {
	some name in _pf_os_domains
	acct := data.cdk_preflight.deploy_account
	is_string(acct)
	a := _pf_os_arn_account(_pf_os_opt(name, "DomainEndpointOptions", "CustomEndpointCertificateArn"))
	a != acct
}
