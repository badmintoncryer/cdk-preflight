package cdk_preflight

import rego.v1

# Every member of ClientAuthentication is optional and each Enabled is an independent Boolean,
# so "all of them false" is a perfectly well-formed template that no client could ever reach. The
# create fails with "Unauthenticated cannot be set to false without enabling any authentication
# mechanisms. ... InvalidParameter: clientAuthentication".
violation contains make_diag_full("pf-msk-unauthenticated-only-requires-no-tls-only", "ERROR", name,
	"Properties.ClientAuthentication",
	"Unauthenticated is false and no authentication mechanism is enabled; the create fails with \"Unauthenticated cannot be set to false without enabling any authentication mechanisms\"",
	"Enable SASL/IAM, SASL/SCRAM or TLS client authentication, or let unauthenticated traffic in",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-clientauthentication.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	object.get(props, ["ClientAuthentication", "Unauthenticated", "Enabled"], true) == false
	not _pf_mskuorn_authenticated(props)
}

_pf_mskuorn_authenticated(props) if object.get(props, ["ClientAuthentication", "Sasl", "Iam", "Enabled"], false) == true

_pf_mskuorn_authenticated(props) if object.get(props, ["ClientAuthentication", "Sasl", "Scram", "Enabled"], false) == true

_pf_mskuorn_authenticated(props) if object.get(props, ["ClientAuthentication", "Tls", "Enabled"], false) == true
