package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-sqlserver-reserved-port", "ERROR", name,
	"Properties.Port",
	sprintf("Port %v is reserved for SQL Server (\"Port 3389 is reserved for this configuration.\")", [n]),
	"Pick another port (1433 is the default)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbinstance.html") if {
	some name in resources_of_type("AWS::RDS::DBInstance")
	_pf_rds_engine_in(name, {"sqlserver-"})
	n := to_number(resolve(name, "Properties.Port"))
	n in {1234, 1434, 3260, 3343, 3389, 47001, 49152, 49153, 49154, 49155, 49156}
}
