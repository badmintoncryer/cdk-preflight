package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-rds-engine-mode-serverless-retired", "ERROR", name,
	"Properties.EngineMode",
	"EngineMode: serverless is Aurora Serverless v1 (\"The engine mode serverless you requested is currently unavailable.\")",
	"Use Serverless v2 (ServerlessV2ScalingConfiguration) instead",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-rds-dbcluster.html") if {
	some name in resources_of_type("AWS::RDS::DBCluster")
	resolve(name, "Properties.EngineMode") == "serverless"
}
