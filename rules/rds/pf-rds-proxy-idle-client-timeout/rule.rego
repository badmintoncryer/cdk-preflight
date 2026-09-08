package cdk_preflight

import rego.v1

_pf_rdspxidle_out(n) if n < 1

_pf_rdspxidle_out(n) if n > 28800

violation contains make_diag_full("pf-rds-proxy-idle-client-timeout", "ERROR", name,
	"Properties.IdleClientTimeout",
	sprintf("IdleClientTimeout %v is outside 1-28800 (\"Invalid IdleClientTimeout - valid range is 1 - 28800\")", [n]),
	"Use a value between 1 and 28800",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbproxy.html") if {
	some name in resources_of_type("AWS::RDS::DBProxy")
	n := to_number(resolve(name, "Properties.IdleClientTimeout"))
	_pf_rdspxidle_out(n)
}
