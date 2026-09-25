package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-policy-name-charset", "ERROR", name,
	"Properties.PolicyName",
	sprintf("PolicyName '%s' has characters outside [A-Za-z0-9_+=,.@-]; CreatePolicy answers \"Value at 'policyName' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w+=,.@-]+\"", [n]),
	"Use only letters, digits and _ + = , . @ - in the policy name",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_CreatePolicy.html") if {
	some name in resources_of_type("AWS::IoT::Policy")
	n := _pf_iotlib_lit(name, "Properties.PolicyName")
	not regex.match(`^[A-Za-z0-9_+=,.@-]+$`, n)
}
