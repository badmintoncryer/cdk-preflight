package cdk_preflight

import rego.v1

_pf_smsn_url := "https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_CreateSecret.html"

_pf_smsn_fix := "Use letters, digits and -/_+=.@! in Name"

violation contains make_diag_full("pf-secretsmanager-secret-name", "ERROR", name,
	"Properties.Name",
	sprintf("'%s' contains characters outside [A-Za-z0-9-/_+=.@!]; CreateSecret fails with \"Invalid name. Must be a valid name containing alphanumeric characters, or any of the following: -/_+=.@!\"", [n]),
	_pf_smsn_fix, _pf_smsn_url) if {
	some name in resources_of_type("AWS::SecretsManager::Secret")
	n := resolve(name, "Properties.Name")
	is_string(n)
	not regex.match("^[A-Za-z0-9/_+=.@!-]+$", n)
}
