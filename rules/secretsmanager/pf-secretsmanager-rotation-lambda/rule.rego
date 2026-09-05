package cdk_preflight

import rego.v1

_pf_smrl_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html"

_pf_smrl_fix := "Set RotationLambdaARN to the ARN of a rotation function in this region (Fn::GetAtt Fn.Arn), or use HostedRotationLambda, but not both"

_pf_smrl_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

# [partition, service, region, account, resource...] of a literal ARN; undefined otherwise
_pf_smrl_arn(s) := parts if {
	is_string(s)
	startswith(s, "arn:")
	parts := split(s, ":")
	count(parts) >= 6
}

_pf_smrl_has(name, k) if object.get(_pf_smrl_props(name), k, "__pf_absent") != "__pf_absent"

violation contains make_diag_full("pf-secretsmanager-rotation-lambda", "ERROR", name,
	"Properties",
	"neither RotationLambdaARN nor HostedRotationLambda is set; the resource handler fails with \"No Lambda rotation function ARN is associated with this secret.\"",
	_pf_smrl_fix, _pf_smrl_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	_pf_smrl_props(name)
	not _pf_smrl_has(name, "RotationLambdaARN")
	not _pf_smrl_has(name, "HostedRotationLambda")
}

violation contains make_diag_full("pf-secretsmanager-rotation-lambda", "ERROR", name,
	"Properties.HostedRotationLambda",
	"both RotationLambdaARN and HostedRotationLambda are set; the AWS::SecretsManager transform fails with \"Can only specify either HostedRotationLambda or RotationLambdaARN\"",
	_pf_smrl_fix, _pf_smrl_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	_pf_smrl_has(name, "RotationLambdaARN")
	_pf_smrl_has(name, "HostedRotationLambda")
}

violation contains make_diag_full("pf-secretsmanager-rotation-lambda", "ERROR", name,
	"Properties.RotationLambdaARN",
	sprintf("'%s' is not a Lambda function ARN; RotateSecret fails with \"Invalid rotation Lambda ARN. Ensure the ARN matches format arn:aws:lambda:<region>:<account>:function:<functionName>.\"", [a]),
	_pf_smrl_fix, _pf_smrl_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	a := resolve(name, "Properties.RotationLambdaARN")
	is_string(a)
	not startswith(a, "arn:")
	not a in object.keys(input.resources)
}

# Region comparison needs the deploy region (enforce mode only).
violation contains make_diag_full("pf-secretsmanager-rotation-lambda", "ERROR", name,
	"Properties.RotationLambdaARN",
	sprintf("rotation function is in '%s' but the schedule deploys to '%s'; RotateSecret fails with \"Invalid rotation Lambda ARN. Ensure the ARN matches format arn:aws:lambda:%s:<account>:function:<functionName>.\"", [parts[3], region, region]),
	_pf_smrl_fix, _pf_smrl_url) if {
	region := data.cdk_preflight.deploy_region
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	parts := _pf_smrl_arn(resolve(name, "Properties.RotationLambdaARN"))
	parts[2] == "lambda"
	parts[3] != region
}
