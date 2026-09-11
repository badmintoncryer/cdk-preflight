package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-querylogconfig-destination-arn-service", "ERROR", name,
	"Properties.DestinationArn",
	sprintf("DestinationArn points at %s; Resolver query logs only go to S3, CloudWatch Logs or Firehose", [svc]),
	"Point DestinationArn at an S3 bucket, a CloudWatch Logs log group or a Firehose delivery stream",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverQueryLogConfig.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverQueryLoggingConfig")
	svc := _pf_r53r_arn_service(_pf_r53r_str(_pf_r53r_props(name), "DestinationArn"))
	not svc in {"s3", "logs", "firehose"}
}
