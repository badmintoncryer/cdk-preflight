package cdk_preflight

import rego.v1

# "If the value is true, FlowLogsS3Bucket and FlowLogsS3Prefix must be specified."
# The registry schema does carry a dependencies clause, but it sits inside each
# property's own boolean/string schema instead of the object schema, where the
# keyword has no meaning - so nothing rejects the half-configured accelerator
# before the handler calls UpdateAcceleratorAttributes.
violation contains make_diag_full("pf-ga-flow-logs-require-bucket-and-prefix", "ERROR", name,
	sprintf("Properties.%s", [missing]),
	sprintf("The accelerator enables flow logs but leaves %v out; both the bucket and the prefix are required once FlowLogsEnabled is true", [missing]),
	"Add FlowLogsS3Bucket and FlowLogsS3Prefix, or drop FlowLogsEnabled",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-globalaccelerator-accelerator.html") if {
	some name in resources_of_type("AWS::GlobalAccelerator::Accelerator")
	_pf_galib_true(_pf_galib_get(name, "FlowLogsEnabled"))
	some missing in {"FlowLogsS3Bucket", "FlowLogsS3Prefix"}
	_pf_galib_absent(name, missing)
}
