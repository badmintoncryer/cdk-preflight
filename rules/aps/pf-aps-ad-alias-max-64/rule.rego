package cdk_preflight

import rego.v1

# The CloudFormation schema caps Alias at 128 characters (a 129-character alias is
# stopped by the bundled engine), but CreateAnomalyDetector caps it at 64, so
# 65..128 is the gap.
violation contains make_diag_full("pf-aps-ad-alias-max-64", "ERROR", name,
	"Properties.Alias",
	sprintf("Alias is %v characters; CreateAnomalyDetector fails with \"Invalid alias: Member must have length less than or equal to 64\"", [count(a)]),
	"Use an alias of at most 64 characters",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-aps-anomalydetector.html") if {
	some name in resources_of_type("AWS::APS::AnomalyDetector")
	a := _pf_aps_str(name, "Properties.Alias")
	count(a) > 64
}
