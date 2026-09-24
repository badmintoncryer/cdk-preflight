package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_region is injected only in enforce mode; the rule
# skips otherwise (warn mode and region-agnostic apps stay silent).
violation contains make_diag_full("pf-opensearch-custom-endpoint-cert-region", "ERROR", name,
	"Properties.DomainEndpointOptions.CustomEndpointCertificateArn",
	sprintf("the certificate is in %v but the domain deploys to %v; CreateDomain answers \"Certificate must be in '%v'.\"", [r, reg, reg]),
	"Import or issue the certificate in the Region the domain deploys into",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/customendpoint.html") if {
	some name in _pf_os_domains
	reg := data.cdk_preflight.deploy_region
	is_string(reg)
	r := _pf_os_arn_region(_pf_os_opt(name, "DomainEndpointOptions", "CustomEndpointCertificateArn"))
	r != reg
}
