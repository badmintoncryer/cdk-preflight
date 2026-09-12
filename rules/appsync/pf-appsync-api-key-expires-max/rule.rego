package cdk_preflight

import rego.v1

# Clock-free subset of the 365-day cap: a value past the year 5138 is over the
# cap whatever the deploy date, and is usually epoch milliseconds.
violation contains make_diag_full("pf-appsync-api-key-expires-max", "ERROR", name,
	"Properties.Expires",
	sprintf("Expires is %v, which is centuries away; the API key create fails because the expiry must be at most 365 days after creation", [e]),
	"Set Expires to a Unix epoch time in seconds at most 365 days from the deploy",
	"https://docs.aws.amazon.com/appsync/latest/APIReference/API_CreateApiKey.html") if {
	some name in resources_of_type("AWS::AppSync::ApiKey")
	e := to_number(resolve(name, "Properties.Expires"))
	e > 100000000000
}
