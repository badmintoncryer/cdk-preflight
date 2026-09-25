package cdk_preflight

import rego.v1

# SigningDisabled defaults to false, so an authorizer that simply leaves it out
# is a signing authorizer and needs the key name too. An intrinsic in
# SigningDisabled is a marker object here, never the literal false, so the rule
# stays silent when the flag is decided at deploy time.
violation contains make_diag_full("pf-iot-authorizer-signing-keys", "ERROR", name,
	"Properties.TokenKeyName",
	"the authorizer signs tokens (SigningDisabled is false or absent) but sets no TokenKeyName; CreateAuthorizer answers \"Token key name for authorizer <name> cannot be null\"",
	"Set TokenKeyName and TokenSigningPublicKeys, or set SigningDisabled to true",
	"https://docs.aws.amazon.com/iot/latest/developerguide/custom-authorizer.html") if {
	some name in resources_of_type("AWS::IoT::Authorizer")
	object.get(_pf_iotlib_props(name), "SigningDisabled", false) == false
	not _pf_iotlib_has(name, "TokenKeyName")
}
