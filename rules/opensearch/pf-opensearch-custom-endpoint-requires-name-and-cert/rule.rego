package cdk_preflight

import rego.v1

_pf_osce_gaps(name) := {k |
	some k, _v in {"CustomEndpoint": 1, "CustomEndpointCertificateArn": 1}
	_pf_os_missing(name, "DomainEndpointOptions", k)
}

violation contains make_diag_full("pf-opensearch-custom-endpoint-requires-name-and-cert", "ERROR", name,
	"Properties.DomainEndpointOptions",
	sprintf("CustomEndpointEnabled is true but %v missing; CreateDomain answers \"Please provide both CustomEndpoint and CustomEndpointCertificateArn fields to create a custom endpoint.\"", [concat(", ", sort(gaps))]),
	"Set CustomEndpoint and CustomEndpointCertificateArn, or turn CustomEndpointEnabled off",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-domainendpointoptions.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "DomainEndpointOptions", "CustomEndpointEnabled")
	gaps := _pf_osce_gaps(name)
	gaps != set()
}
