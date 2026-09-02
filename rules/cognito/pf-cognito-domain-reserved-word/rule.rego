package cdk_preflight

import rego.v1

# The service refuses prefixes with a reserved word as a hyphen-delimited
# token, with only a generic error. Pinned by controlled pairs: -aws- /
# -amazon- / -cognito- fail while -awsome- deploys (bench c07-c07e), so
# a token merely containing a word stays legal.
_pf_cogdrw_words := {"aws", "amazon", "cognito"}

violation contains make_diag_full("pf-cognito-domain-reserved-word", "ERROR", name,
	"Properties.Domain",
	sprintf("Domain prefix '%s' has the reserved word '%s' as a segment; the domain create fails with the generic \"Invalid request provided: AWS::Cognito::UserPoolDomain\"", [d, w]),
	"Rename or merge that segment (e.g. myapp-auth); words merely inside a longer segment are fine",
	"https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-assign-domain-prefix.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolDomain")
	d := resolve(name, "Properties.Domain")
	is_string(d)
	some w in _pf_cogdrw_words
	w in split(d, "-")
}
