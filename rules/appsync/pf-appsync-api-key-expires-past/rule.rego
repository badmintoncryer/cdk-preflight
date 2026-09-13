package cdk_preflight

import rego.v1

# The engine has no clock (time.now_ns is not available), so only values that
# cannot be in the future under any deploy date are judged - typically a
# duration or a millisecond value passed where epoch seconds are expected.
violation contains make_diag_full("pf-appsync-api-key-expires-past", "ERROR", name,
	"Properties.Expires",
	sprintf("Expires is %v, which is before 2001-09-09; the API key create fails because the expiry has to be a future Unix timestamp in seconds", [e]),
	"Set Expires to a Unix epoch time in seconds between 1 and 365 days from the deploy",
	"https://docs.aws.amazon.com/appsync/latest/APIReference/API_CreateApiKey.html") if {
	some name in resources_of_type("AWS::AppSync::ApiKey")
	e := to_number(resolve(name, "Properties.Expires"))
	e < 1000000000
}
