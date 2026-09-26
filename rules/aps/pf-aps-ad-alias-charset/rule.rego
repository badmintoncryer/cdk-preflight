package cdk_preflight

import rego.v1

# The CloudFormation schema carries no pattern for Alias at all. The service
# full-matches it: a leading hyphen is rejected even though every character is in
# the trailing class.
violation contains make_diag_full("pf-aps-ad-alias-charset", "ERROR", name,
	"Properties.Alias",
	sprintf("Alias \"%v\" is not a full match for [0-9A-Za-z][-.0-9A-Z_a-z]*; CreateAnomalyDetector fails with \"Invalid alias: Member must satisfy regular expression pattern: [0-9A-Za-z][-.0-9A-Z_a-z]*\"", [a]),
	"Start the alias with a letter or digit and use only letters, digits, hyphens, dots and underscores",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-aps-anomalydetector.html") if {
	some name in resources_of_type("AWS::APS::AnomalyDetector")
	a := _pf_aps_str(name, "Properties.Alias")
	not regex.match(`^[0-9A-Za-z][-.0-9A-Z_a-z]*$`, a)
}
