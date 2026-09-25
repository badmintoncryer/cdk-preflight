package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iot-rolealias-name-charset", "ERROR", name,
	"Properties.RoleAlias",
	sprintf("RoleAlias '%s' has characters outside [A-Za-z0-9_=,@-]; CreateRoleAlias answers \"Value at 'roleAlias' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w=,@-]+\"", [n]),
	"Use only letters, digits and _ = , @ - in the role alias (no dot, no plus)",
	"https://docs.aws.amazon.com/iot/latest/apireference/API_CreateRoleAlias.html") if {
	some name in resources_of_type("AWS::IoT::RoleAlias")
	n := _pf_iotlib_lit(name, "Properties.RoleAlias")
	not regex.match(`^[A-Za-z0-9_=,@-]+$`, n)
}
