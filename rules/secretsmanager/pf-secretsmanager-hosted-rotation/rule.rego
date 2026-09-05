package cdk_preflight

import rego.v1

_pf_smhr_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-secretsmanager-rotationschedule-hostedrotationlambda.html"

_pf_smhr_fix := "Add Transform: AWS::SecretsManager-2024-09-16 at the template top level, pick a RotationType from the documented list, and drop Runtime"

_pf_smhr_props(name) := props if {
	props := input.resources[name].properties
	is_object(props)
}

_pf_smhr_hosted(name) := h if {
	h := object.get(_pf_smhr_props(name), "HostedRotationLambda", null)
	is_object(h)
}

# the engine exposes the template's Transform list as input.template.transforms
_pf_smhr_transforms := t if {
	t := object.get(input.template, "transforms", null)
	is_array(t)
}

_pf_smhr_transforms := [] if not is_array(object.get(input.template, "transforms", null))

_pf_smhr_has_transform if {
	some t in _pf_smhr_transforms
	is_string(t)
	startswith(t, "AWS::SecretsManager-")
}

violation contains make_diag_full("pf-secretsmanager-hosted-rotation", "ERROR", name,
	"Properties.HostedRotationLambda",
	"HostedRotationLambda is used but the template has no Transform: AWS::SecretsManager-2024-09-16; the resource handler fails with \"To use the HostedRotationLambda property, you must use the AWS::SecretsManager transform\"",
	_pf_smhr_fix, _pf_smhr_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	_pf_smhr_hosted(name)
	not _pf_smhr_has_transform
}

_pf_smhr_types := ["Db2SingleUser", "Db2MultiUser", "MySQLSingleUser", "MySQLMultiUser", "PostgreSQLSingleUser", "PostgreSQLMultiUser", "OracleSingleUser", "OracleMultiUser", "MariaDBSingleUser", "MariaDBMultiUser", "SQLServerSingleUser", "SQLServerMultiUser", "RedshiftSingleUser", "RedshiftMultiUser", "MongoDBSingleUser", "MongoDBMultiUser"]

violation contains make_diag_full("pf-secretsmanager-hosted-rotation", "ERROR", name,
	"Properties.HostedRotationLambda.RotationType",
	sprintf("RotationType '%s' is not one of the rotation function templates; the AWS::SecretsManager transform fails with \"%s is not a supported rotation engine type\"", [t, t]),
	_pf_smhr_fix, _pf_smhr_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	t := resolve(name, "Properties.HostedRotationLambda.RotationType")
	is_string(t)
	not t in _pf_smhr_types
}

violation contains make_diag_full("pf-secretsmanager-hosted-rotation", "ERROR", name,
	sprintf("Properties.HostedRotationLambda.%s", [k]),
	sprintf("%s is only meaningful for the alternating-users (*MultiUser) templates, not %s; the AWS::SecretsManager transform fails with \"Parameters: [masterSecretArn] do not exist in the template\"", [k, t]),
	_pf_smhr_fix, _pf_smhr_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	h := _pf_smhr_hosted(name)
	t := resolve(name, "Properties.HostedRotationLambda.RotationType")
	is_string(t)
	not endswith(t, "MultiUser")
	some k in ["MasterSecretArn", "SuperuserSecretArn"]
	object.get(h, k, "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-secretsmanager-hosted-rotation", "ERROR", name,
	"Properties.HostedRotationLambda.SuperuserSecretArn",
	"MasterSecretArn and SuperuserSecretArn name the same superuser secret and cannot both be set; the AWS::SecretsManager transform fails with \"You can't specify both masterSecretArn and superuserSecretArn in the same Lambda rotation function.\"",
	_pf_smhr_fix, _pf_smhr_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	h := _pf_smhr_hosted(name)
	object.get(h, "MasterSecretArn", "__pf_absent") != "__pf_absent"
	object.get(h, "SuperuserSecretArn", "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-secretsmanager-hosted-rotation", "ERROR", name,
	"Properties.HostedRotationLambda.Runtime",
	"Runtime must not be set with Transform AWS::SecretsManager-2024-09-16 (the vended rotation function ships its own runtime); the nested rotation stack fails to create",
	_pf_smhr_fix, _pf_smhr_url) if {
	some name in resources_of_type("AWS::SecretsManager::RotationSchedule")
	h := _pf_smhr_hosted(name)
	object.get(h, "Runtime", "__pf_absent") != "__pf_absent"
	some t in _pf_smhr_transforms
	t == "AWS::SecretsManager-2024-09-16"
}
