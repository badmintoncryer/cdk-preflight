package cdk_preflight

import rego.v1

_pf_smsx_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secret.html"

_pf_smsx_fix := "Keep either SecretString (a literal value) or GenerateSecretString (a generated password), not both"

_pf_smsx_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

violation contains make_diag_full("pf-secretsmanager-secret-string-exclusive", "ERROR", name,
	"Properties.GenerateSecretString",
	"both SecretString and GenerateSecretString are set; the resource handler fails with \"Can only specify either SecretString or GenerateSecretString.\"",
	_pf_smsx_fix, _pf_smsx_url) if {
	some name in resources_of_type("AWS::SecretsManager::Secret")
	p := _pf_smsx_props(name)
	object.get(p, "SecretString", "__pf_absent") != "__pf_absent"
	object.get(p, "GenerateSecretString", "__pf_absent") != "__pf_absent"
}
