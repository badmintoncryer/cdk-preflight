package cdk_preflight

import rego.v1

# "To turn on SASL, you must also turn on EncryptionInTransit by setting inCluster to true."
# InCluster defaults to true, so only an explicit false is a problem, and the create then fails
# with "To turn on client authentication, you must also turn on in-cluster encryption. ...
# InvalidParameter: clientAuthentication".
violation contains make_diag_full("pf-msk-sasl-requires-in-cluster-encryption", "ERROR", name,
	"Properties.EncryptionInfo.EncryptionInTransit.InCluster",
	"client authentication is turned on with InCluster false; the create fails with \"To turn on client authentication, you must also turn on in-cluster encryption\"",
	"Set InCluster to true (its default), or turn client authentication off",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-clientauthentication.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	props := input.resources[name].properties
	is_object(props)
	_pf_msksrice_authenticated(props)
	object.get(props, ["EncryptionInfo", "EncryptionInTransit", "InCluster"], _pf_default("pf-msk-sasl-requires-in-cluster-encryption", "EncryptionInTransit.InCluster")) == false
}

_pf_msksrice_authenticated(props) if object.get(props, ["ClientAuthentication", "Sasl", "Iam", "Enabled"], _pf_default("pf-msk-sasl-requires-in-cluster-encryption", "ClientAuthentication.Sasl.Iam.Enabled")) == true

_pf_msksrice_authenticated(props) if _pf_oval(props, ["ClientAuthentication", "Sasl", "Scram", "Enabled"]) == true

_pf_msksrice_authenticated(props) if _pf_oval(props, ["ClientAuthentication", "Tls", "Enabled"]) == true
