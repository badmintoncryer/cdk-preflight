package cdk_preflight

import rego.v1

_pf_gfsaml_idp(name) := md if {
	saml := object.get(_pf_grafana_props(name), "SamlConfiguration", null)
	is_object(saml)
	md := object.get(saml, "IdpMetadata", null)
	is_object(md)
}

# IdpMetadata is required inside SamlConfiguration and both of its members are
# optional, so the schema accepts an empty object — which is exactly what cdk
# renders for { url: undefined, xml: undefined }. The service answers the generic
# BadRequestException: Invalid request body, naming no property at all.
#
# Only a literally empty object is reported, so an Fn::If marker (one key) stays
# silent.
violation contains make_diag_full("pf-grafana-ws-saml-idp-metadata-source", "ERROR", name,
	"Properties.SamlConfiguration.IdpMetadata",
	"IdpMetadata names neither Url nor Xml; UpdateWorkspaceAuthentication fails with \"Invalid request body\", which names no property",
	"Point IdpMetadata at the identity provider's metadata Url, or inline the metadata as Xml",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-grafana-workspace-idpmetadata.html") if {
	some name in resources_of_type("AWS::Grafana::Workspace")
	count(_pf_gfsaml_idp(name)) == 0
}

# The two members are exclusive, not alternative: naming both is rejected with the
# same generic sentence as naming neither (measured on both layers 2026-09-26).
violation contains make_diag_full("pf-grafana-ws-saml-idp-metadata-source", "ERROR", name,
	"Properties.SamlConfiguration.IdpMetadata",
	"IdpMetadata names both Url and Xml; the two are exclusive and UpdateWorkspaceAuthentication fails with \"Invalid request body\", which names no property",
	"Keep either Url or Xml, not both",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-grafana-workspace-idpmetadata.html") if {
	some name in resources_of_type("AWS::Grafana::Workspace")
	md := _pf_gfsaml_idp(name)
	object.get(md, "Url", "__pf_absent") != "__pf_absent"
	object.get(md, "Xml", "__pf_absent") != "__pf_absent"
}
