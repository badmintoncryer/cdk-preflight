package cdk_preflight

import rego.v1

# One service-side pattern check covers the charset, the 255 character limit
# and the wildcard position, so it is one rule here too.
violation contains make_diag_full("pf-batch-sp-share-identifier-pattern", "ERROR", name,
	"Properties.FairsharePolicy.ShareDistribution",
	sprintf("share identifier %v is rejected by the service: letters, numbers, hyphen and underscore, an optional trailing \"*\", at most 255 characters (\"ShareIdentifier name should match a valid pattern.\")", [si]),
	"Rename the share identifier, and keep any wildcard as the last character",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ShareAttributes.html") if {
	some name in resources_of_type("AWS::Batch::SchedulingPolicy")
	some e in flatten_list(name, "Properties.FairsharePolicy.ShareDistribution")
	si := _pf_batch_oget(e.value, "ShareIdentifier")
	is_string(si)
	not regex.match(`^[a-zA-Z0-9_-]{1,254}[a-zA-Z0-9_*-]?$`, si)
}
