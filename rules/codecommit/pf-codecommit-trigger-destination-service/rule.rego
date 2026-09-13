package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-codecommit-trigger-destination-service", "ERROR", name,
	sprintf("Properties.Triggers.%d.DestinationArn", [i]),
	sprintf("The trigger destination is a %s ARN; the handler's PutRepositoryTriggers fails with \"Unexpected service name in arn: %s\"", [svc, svc]),
	"Point the trigger at an SNS topic or a Lambda function",
	"https://docs.aws.amazon.com/codecommit/latest/APIReference/API_PutRepositoryTriggers.html") if {
	some name in resources_of_type("AWS::CodeCommit::Repository")
	some i, t in _pf_cclib_triggers(name)
	is_object(t)
	parts := _pf_cclib_arn(object.get(t, "DestinationArn", ""))
	svc := parts[2]
	not svc in {"sns", "lambda"}
}
