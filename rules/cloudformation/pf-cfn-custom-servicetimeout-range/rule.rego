package cdk_preflight

import rego.v1

# ServiceTimeout is a plain string in the template and neither the schema nor
# any L2 range-checks it. The documented ceiling is 3600, but the service
# accepts up to 14400 (measured 2026-09-25: 14400 accepted, 14401 rejected).
_pf_cfnsvctmo_out(n) if n < 1

_pf_cfnsvctmo_out(n) if n > 14400

_pf_cfnsvctmo_bad contains [name, n] if {
	some name in _pf_cfn_custom_resources
	n := to_number(resolve(name, "Properties.ServiceTimeout"))
	_pf_cfnsvctmo_out(n)
}

violation contains make_diag_full("pf-cfn-custom-servicetimeout-range", "ERROR", name,
	"Properties.ServiceTimeout",
	sprintf("ServiceTimeout is %v; CloudFormation fails the resource with \"ServiceTimeout must be an integer between 1 and 14400 seconds\"", [n]),
	"Set ServiceTimeout to a whole number of seconds between 1 and 14400",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudformation-customresource.html") if {
	some [name, n] in _pf_cfnsvctmo_bad
}
