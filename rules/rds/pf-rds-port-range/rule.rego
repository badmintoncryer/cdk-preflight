package cdk_preflight

import rego.v1

_pf_rdsport_out(n) if n < 1150

_pf_rdsport_out(n) if n > 65535

violation contains make_diag_full("pf-rds-port-range", "ERROR", name,
	"Properties.Port",
	sprintf("Port %v is outside 1150-65535 (\"Invalid endpoint port %v. Valid range is: 1150-65535\")", [n, n]),
	"Pick a port between 1150 and 65535",
	"https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	n := to_number(resolve(name, "Properties.Port"))
	_pf_rdsport_out(n)
}
