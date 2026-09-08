package cdk_preflight

import rego.v1

_pf_rdspool_pct_out(n) if n < 1

_pf_rdspool_pct_out(n) if n > 100

_pf_rdspool_timeout_out(n) if n < 0

_pf_rdspool_timeout_out(n) if n > 300

violation contains make_diag_full("pf-rds-proxy-pool-percent", "ERROR", name,
	"Properties.ConnectionPoolConfigurationInfo.MaxIdleConnectionsPercent",
	sprintf("MaxIdleConnectionsPercent %v is above MaxConnectionsPercent %v", [idle, mx]),
	"Keep MaxIdleConnectionsPercent at or below MaxConnectionsPercent",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-rds-dbproxytargetgroup-connectionpoolconfigurationinfo.html") if {
	some name in resources_of_type("AWS::RDS::DBProxyTargetGroup")
	idle := to_number(resolve(name, "Properties.ConnectionPoolConfigurationInfo.MaxIdleConnectionsPercent"))
	mx := to_number(resolve(name, "Properties.ConnectionPoolConfigurationInfo.MaxConnectionsPercent"))
	idle > mx
}

violation contains make_diag_full("pf-rds-proxy-pool-percent", "ERROR", name,
	"Properties.ConnectionPoolConfigurationInfo.MaxConnectionsPercent",
	sprintf("MaxConnectionsPercent %v is outside 1-100", [mx]),
	"Use a value between 1 and 100",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-rds-dbproxytargetgroup-connectionpoolconfigurationinfo.html") if {
	some name in resources_of_type("AWS::RDS::DBProxyTargetGroup")
	mx := to_number(resolve(name, "Properties.ConnectionPoolConfigurationInfo.MaxConnectionsPercent"))
	_pf_rdspool_pct_out(mx)
}

violation contains make_diag_full("pf-rds-proxy-pool-percent", "ERROR", name,
	"Properties.ConnectionPoolConfigurationInfo.ConnectionBorrowTimeout",
	sprintf("ConnectionBorrowTimeout %v is outside 0-300 seconds", [t]),
	"Use a value between 0 and 300",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-rds-dbproxytargetgroup-connectionpoolconfigurationinfo.html") if {
	some name in resources_of_type("AWS::RDS::DBProxyTargetGroup")
	t := to_number(resolve(name, "Properties.ConnectionPoolConfigurationInfo.ConnectionBorrowTimeout"))
	_pf_rdspool_timeout_out(t)
}
