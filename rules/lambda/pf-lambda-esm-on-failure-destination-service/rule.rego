package cdk_preflight

import rego.v1

_pf_leods_fix := "Point OnFailure.Destination at an SNS topic, SQS queue, S3 bucket or Kafka topic ARN"

_pf_leods_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-lambda-eventsourcemapping-onfailure.html"

_pf_leods_ok := {"sns", "sqs", "s3", "kafka"}

violation contains make_diag_full("pf-lambda-esm-on-failure-destination-service", "ERROR", name,
	"Properties.DestinationConfig.OnFailure.Destination",
	sprintf("the on-failure destination names the '%v' service; Lambda writes failure records only to SNS, SQS, S3 or a Kafka topic", [parts[2]]),
	_pf_leods_fix, _pf_leods_url) if {
	some name in _pf_lam_esm
	parts := _pf_lam_arn(resolve(name, "Properties.DestinationConfig.OnFailure.Destination"))
	not parts[2] in _pf_leods_ok
}
