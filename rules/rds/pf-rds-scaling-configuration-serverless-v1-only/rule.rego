package cdk_preflight

import rego.v1

_pf_rdsv1_notserverless(name) if not _pf_rds_has(name, "EngineMode")

_pf_rdsv1_notserverless(name) if {
	m := _pf_rds_get(name, "EngineMode")
	is_string(m)
	m != "serverless"
}

violation contains make_diag_full("pf-rds-scaling-configuration-serverless-v1-only", "ERROR", name,
	"Properties.ScalingConfiguration",
	"ScalingConfiguration is set on a cluster that is not EngineMode: serverless (\"You can only specify scaling configuration for an Aurora Serverless v1 cluster.\")",
	"Use ServerlessV2ScalingConfiguration for Serverless v2",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	_pf_rds_has(name, "ScalingConfiguration")
	_pf_rdsv1_notserverless(name)
}
