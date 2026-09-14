package cdk_preflight

import rego.v1

# Both members of Tls are Required: No, so half a block is schema-valid; the resource handler
# rejects it before it ever calls Kafka - "Enabled and CertificateAuthorityArnList fields must
# both be defined for TLS. 'TLS'". The requirement is symmetric: neither half stands on its own.
violation contains make_diag_full("pf-msk-tls-enabled-requires-ca-list", "ERROR", name,
	"Properties.ClientAuthentication.Tls",
	"the Tls block defines only one of Enabled and CertificateAuthorityArnList; the create fails with \"Enabled and CertificateAuthorityArnList fields must both be defined for TLS\"",
	"Write both fields, or drop the Tls block altogether",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-tls.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	tls := object.get(props, ["ClientAuthentication", "Tls"], null)
	is_object(tls)
	not _pf_msktercl_complete(name, tls)
}

_pf_msktercl_complete(name, tls) if {
	object.get(tls, "Enabled", "__pf_absent") != "__pf_absent"
	count(flatten_list(name, "Properties.ClientAuthentication.Tls.CertificateAuthorityArnList")) > 0
}
