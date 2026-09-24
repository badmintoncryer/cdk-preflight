package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-saml-requires-fgac", "ERROR", name,
	"Properties.AdvancedSecurityOptions.SAMLOptions",
	"SAMLOptions is configured while advanced security is off; CreateDomain answers \"Advanced security option must be enabled to configure SAML.\"",
	"Set AdvancedSecurityOptions.Enabled to true (with encryption at rest, node-to-node encryption, EnforceHTTPS and a master user), or drop SAMLOptions",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-advancedsecurityoptionsinput.html") if {
	some name in _pf_os_domains
	_pf_os_on3(name, "AdvancedSecurityOptions", "SAMLOptions", "Enabled")
	not _pf_os_on(name, "AdvancedSecurityOptions", "Enabled")
}
