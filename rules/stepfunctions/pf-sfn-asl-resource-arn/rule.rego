package cdk_preflight

import rego.v1

_pf_sfnres_url := "https://docs.aws.amazon.com/step-functions/latest/dg/integrate-optimized.html"

_pf_sfnres_fix := "Use the integration pattern the service supports (see the optimized integrations table); a Lambda call waits for the function anyway (no .sync)"

violation contains make_diag_full("pf-sfn-asl-resource-arn", "ERROR", name,
	sprintf("%s.Resource", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("Task state '%s' Resource '%s' is not an ARN; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: Value is not a valid resource ARN\"", [sname, res]),
	_pf_sfnres_fix, _pf_sfnres_url) if {
	some [name, p, s, sname, st] in _pf_sfnlib_states
	object.get(st, "Type", null) == "Task"
	res := object.get(st, "Resource", null)
	is_string(res)
	not contains(res, "${")
	not startswith(res, "arn:")
}

# Services whose optimized integration never offers the pattern (doc table,
# confirmed with ValidateStateMachineDefinition on 2026-09-05). Support on the
# positive side is per API, so only the impossible combinations are judged.
_pf_sfnres_nosync := {"lambda", "sns", "sqs", "dynamodb", "events", "apigateway", "aws-sdk", "bedrock-agentcore"}

_pf_sfnres_notoken := {"athena", "batch", "codebuild", "elasticmapreduce", "emr-containers", "emr-serverless", "glue", "databrew", "mediaconvert", "sagemaker", "dynamodb", "bedrock-agentcore"}

violation contains make_diag_full("pf-sfn-asl-resource-arn", "ERROR", name,
	sprintf("%s.Resource", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("Task state '%s' uses the .sync (Run a Job) pattern on the %s integration, which does not support it; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: The resource provided arn:aws:states:::%s:%s is not recognized\"", [sname, svc, svc, api]),
	_pf_sfnres_fix, _pf_sfnres_url) if {
	some [name, p, s, sname, st, svc, api] in _pf_sfnlib_integration
	svc in _pf_sfnres_nosync
	regex.match("[.]sync(:2)?$", api)
}

violation contains make_diag_full("pf-sfn-asl-resource-arn", "ERROR", name,
	sprintf("%s.Resource", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("Task state '%s' uses the .waitForTaskToken (callback) pattern on the %s integration, which does not support it; CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: The resource provided arn:aws:states:::%s:%s is not recognized\"", [sname, svc, svc, api]),
	_pf_sfnres_fix, _pf_sfnres_url) if {
	some [name, p, s, sname, st, svc, api] in _pf_sfnlib_integration
	svc in _pf_sfnres_notoken
	endswith(api, ".waitForTaskToken")
}

violation contains make_diag_full("pf-sfn-asl-resource-arn", "ERROR", name,
	sprintf("%s.Resource", [_pf_sfnlib_path(name, p, sname)]),
	sprintf("Task state '%s' uses .sync:2 on %s:%s; only states:startExecution.sync:2 exists, and CreateStateMachine fails with \"SCHEMA_VALIDATION_FAILED: The resource provided ... is not recognized\"", [sname, svc, api]),
	_pf_sfnres_fix, _pf_sfnres_url) if {
	some [name, p, s, sname, st, svc, api] in _pf_sfnlib_integration
	endswith(api, ".sync:2")
	svc != "states"
}
