package cdk_preflight

import rego.v1

# IAM access control is the only client authentication MSK Serverless has. The CloudFormation
# schema makes ClientAuthentication.Sasl.Iam.Enabled required, so the reachable mistake is setting
# it to false -- which the schema happily accepts and CreateClusterV2 rejects with "A serverless
# cluster must use SASL/IAM authentication".
violation contains make_diag_full("pf-msk-serverless-sasl-iam-enabled", "ERROR", name,
	"Properties.ClientAuthentication.Sasl.Iam.Enabled",
	"SASL/IAM authentication is disabled; a serverless cluster has no other client authentication and the create fails with \"A serverless cluster must use SASL/IAM authentication\"",
	"Set ClientAuthentication.Sasl.Iam.Enabled to true",
	"https://docs.aws.amazon.com/msk/latest/developerguide/serverless.html") if {
	some name in resources_of_type("AWS::MSK::ServerlessCluster")
	resolve(name, "Properties.ClientAuthentication.Sasl.Iam.Enabled") == false
}
