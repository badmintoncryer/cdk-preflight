package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-proxy-target-group-name", "ERROR", name,
	"Properties.TargetGroupName",
	sprintf("TargetGroupName %v is not \"default\"; RDS only supports the default target group", [n]),
	"Use \"default\"",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-rds-dbproxytargetgroup-connectionpoolconfigurationinfo.html") if {
	some name in resources_of_type("AWS::RDS::DBProxyTargetGroup")
	n := resolve(name, "Properties.TargetGroupName")
	is_string(n)
	not input.resources[n]
	n != "default"
}
