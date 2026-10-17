package cdk_preflight

import rego.v1

# The primary identifier is ProfileId, so the schema says nothing about
# Name, but CreateBrowserProfile fails with "Browser profile with name '...'
# already exists in this account" (ConflictException). Only names inside one
# template are compared, as written.
violation contains make_diag_full("pf-agentcore-browser-profile-name-unique", "ERROR", name,
	"Properties.Name",
	sprintf("Browser profile name '%s' is already used by resource '%s'; CreateBrowserProfile fails with \"Browser profile with name '%s' already exists in this account\"", [n, other, n]),
	"Give each browser profile its own Name",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateBrowserProfile.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::BrowserProfile")
	n := resolve(name, "Properties.Name")
	is_string(n)
	some other in resources_of_type("AWS::BedrockAgentCore::BrowserProfile")
	other < name
	resolve(other, "Properties.Name") == n
}
