package cdk_preflight

import rego.v1

# "You must set clientBroker to either TLS or TLS_PLAINTEXT" - a cluster that authenticates its
# clients over a plaintext listener is rejected with "Client-broker encryption in transit must be
# set to either TLS or TLS_PLAINTEXT to enable client authentication. ... InvalidParameter:
# clientAuthentication". Both members are independently valid, so nothing earlier sees the pair.
violation contains make_diag_full("pf-msk-sasl-requires-tls-client-broker", "ERROR", name,
	"Properties.EncryptionInfo.EncryptionInTransit.ClientBroker",
	"client authentication is turned on with ClientBroker PLAINTEXT; the create fails with \"Client-broker encryption in transit must be set to either TLS or TLS_PLAINTEXT to enable client authentication\"",
	"Set ClientBroker to TLS (or TLS_PLAINTEXT), or turn client authentication off",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-clientauthentication.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	_pf_msksrtcb_authenticated(props)
	object.get(props, ["EncryptionInfo", "EncryptionInTransit", "ClientBroker"], "TLS") == "PLAINTEXT"
}

# Any client authentication mechanism explicitly switched on.
_pf_msksrtcb_authenticated(props) if object.get(props, ["ClientAuthentication", "Sasl", "Iam", "Enabled"], false) == true

_pf_msksrtcb_authenticated(props) if object.get(props, ["ClientAuthentication", "Sasl", "Scram", "Enabled"], false) == true

_pf_msksrtcb_authenticated(props) if object.get(props, ["ClientAuthentication", "Tls", "Enabled"], false) == true
