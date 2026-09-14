package cdk_preflight

import rego.v1

# "If you choose TLS_PLAINTEXT, then you must also set unauthenticated to true" - the plaintext
# half of the listener has no authentication to offer, so the create fails with "You must enable
# unauthenticated traffic explicitly to use client-authentication using SASL over TLS_PLAINTEXT.
# ... InvalidParameter: clientAuthentication".
violation contains make_diag_full("pf-msk-tls-plaintext-requires-unauthenticated", "ERROR", name,
	"Properties.ClientAuthentication.Unauthenticated.Enabled",
	"ClientBroker TLS_PLAINTEXT with client authentication but without Unauthenticated.Enabled; the create fails with \"You must enable unauthenticated traffic explicitly to use client-authentication using SASL over TLS_PLAINTEXT\"",
	"Set ClientAuthentication.Unauthenticated.Enabled to true, or move ClientBroker to TLS",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-clientauthentication.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	object.get(props, ["EncryptionInfo", "EncryptionInTransit", "ClientBroker"], "TLS") == "TLS_PLAINTEXT"
	_pf_msktpru_authenticated(props)
	object.get(props, ["ClientAuthentication", "Unauthenticated", "Enabled"], false) != true
}

_pf_msktpru_authenticated(props) if object.get(props, ["ClientAuthentication", "Sasl", "Iam", "Enabled"], false) == true

_pf_msktpru_authenticated(props) if object.get(props, ["ClientAuthentication", "Sasl", "Scram", "Enabled"], false) == true

_pf_msktpru_authenticated(props) if object.get(props, ["ClientAuthentication", "Tls", "Enabled"], false) == true
