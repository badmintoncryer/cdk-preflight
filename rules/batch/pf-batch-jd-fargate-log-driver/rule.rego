package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-fargate-log-driver", "ERROR", name,
	"Properties.ContainerProperties.LogConfiguration.LogDriver",
	sprintf("a Fargate job definition uses the %v log driver (\"Log driver for Fargate is not valid: %v\")", [d, d]),
	"Use awslogs, splunk or awsfirelens",
	"https://docs.aws.amazon.com/batch/latest/userguide/fargate-job-definitions.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_fargate(name)
	d := _pf_batch_oget(_pf_batch_cpget(name, "LogConfiguration"), "LogDriver")
	_pf_batch_lit(d)
	not d in {"awslogs", "splunk", "awsfirelens"}
}
