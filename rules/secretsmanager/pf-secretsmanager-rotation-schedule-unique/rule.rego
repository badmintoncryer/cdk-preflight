package cdk_preflight

import rego.v1

_pf_smru_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-rotationschedule.html"

_pf_smru_fix := "Keep a single RotationSchedule per secret"

_pf_smru_target(name) := t if {
	t := resolve(name, "Properties.SecretId")
	is_string(t)
}

violation contains make_diag_full("pf-secretsmanager-rotation-schedule-unique", "ERROR", name,
	"Properties.SecretId",
	sprintf("secret '%s' already has a rotation schedule ('%s'); the second RotateSecret call fails with \"A previous rotation isn't complete. That rotation will be reattempted.\"", [t, other]),
	_pf_smru_fix, _pf_smru_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	t := _pf_smru_target(name)
	some other in resources_of_type("AWS::SecretsManager::RotationSchedule")
	other < name
	_pf_smru_target(other) == t
}
