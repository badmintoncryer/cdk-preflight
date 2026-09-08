package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-infrequent-access-transformer", "ERROR", name,
	"Properties.LogGroupIdentifier",
	"The target log group uses the Infrequent Access log class; PutTransformer fails with \"This operation is only supported on the Standard log class.\"",
	"Put the log group in the Standard class (LogGroupClass: STANDARD, the default), or drop this resource",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-logs-loggroup.html") if {
	some name in resources_of_type("AWS::Logs::Transformer")
	_pf_lglib_ia_target(name, "Properties.LogGroupIdentifier")
}
