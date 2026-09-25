package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-authorizer-name-charset", "ERROR", name,
	"Properties.AuthorizerName",
	sprintf("AuthorizerName '%s' has characters outside [A-Za-z0-9_=,@-]; CreateAuthorizer answers \"Value at 'authorizerName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w=,@-]+\"", [n]),
	"Use only letters, digits and _ = , @ - in the authorizer name (no dot, no plus)",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_CreateAuthorizer.html") if {
	some name in resources_of_type("AWS::IoT::Authorizer")
	n := _pf_iotlib_lit(name, "Properties.AuthorizerName")
	not regex.match(`^[A-Za-z0-9_=,@-]+$`, n)
}
