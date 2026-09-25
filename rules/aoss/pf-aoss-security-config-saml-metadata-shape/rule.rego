package cdk_preflight

import rego.v1

# Metadata is a 1-51200 character string to every schema layer. The service
# parses it and pulls exactly two things out of the IDPSSODescriptor - the
# SingleSignOnService Location (IdpURL) and the X509Certificate (Cert) - and
# rejects the config when either is missing, which is what happens when a
# service-provider metadata file is pasted in place of the identity provider's.
# Substring checks, not XML parsing: both element names are fixed by the SAML
# metadata schema and survive any namespace prefix.

_pf_aoss_md_fix := "Use the identity provider's metadata XML, the one whose IDPSSODescriptor carries a SingleSignOnService Location and a signing X509Certificate"

violation contains make_diag_full("pf-aoss-security-config-saml-metadata-shape", "ERROR", name,
	"Properties.SamlOptions.Metadata",
	"the SAML metadata has no SingleSignOnService element; CreateSecurityConfig answers \"Policy json is invalid, error: [$.IdpURL: null found, string expected]\"",
	_pf_aoss_md_fix, "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-saml.html") if {
	some name in resources_of_type("AWS::OpenSearchServerless::SecurityConfig")
	m := resolve(name, "Properties.SamlOptions.Metadata")
	is_string(m)
	not contains(m, "SingleSignOnService")
}

violation contains make_diag_full("pf-aoss-security-config-saml-metadata-shape", "ERROR", name,
	"Properties.SamlOptions.Metadata",
	"the SAML metadata has no X509Certificate element; CreateSecurityConfig answers \"Policy json is invalid, error: [$.Cert: null found, string expected]\"",
	_pf_aoss_md_fix, "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-saml.html") if {
	some name in resources_of_type("AWS::OpenSearchServerless::SecurityConfig")
	m := resolve(name, "Properties.SamlOptions.Metadata")
	is_string(m)
	not contains(m, "X509Certificate")
}
