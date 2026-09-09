package cdk_preflight

import rego.v1

# PreTokenGenerationConfig supersedes PreTokenGeneration; the service keeps
# both in sync and rejects two different ARNs.

violation contains make_diag_full("pf-cognito-pre-token-generation-legacy-mix", "ERROR", name,
	"Properties.LambdaConfig.PreTokenGenerationConfig.LambdaArn",
	"PreTokenGeneration and PreTokenGenerationConfig.LambdaArn name different functions; the pool create fails with \"Cannot use PreTokenGenerationLambda and PreTokenGeneration with different Lambda function ARN's\"",
	"Point both at the same function ARN, or set only PreTokenGenerationConfig",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	legacy := _pf_coglib_str(_pf_coglib_g2(name, "LambdaConfig", "PreTokenGeneration"))
	v2 := _pf_coglib_str(_pf_coglib_g3(name, "LambdaConfig", "PreTokenGenerationConfig", "LambdaArn"))
	legacy != v2
}
