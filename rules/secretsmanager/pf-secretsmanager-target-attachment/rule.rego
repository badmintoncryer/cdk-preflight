package cdk_preflight

import rego.v1

_pf_smta_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-secretsmanager-secrettargetattachment.html"

_pf_smta_fix := "Give the secret a JSON object value (GenerateSecretString with SecretStringTemplate/GenerateStringKey, or a JSON SecretString) and use one of the seven TargetType values"

_pf_smta_types := ["AWS::RDS::DBInstance", "AWS::RDS::DBCluster", "AWS::Redshift::Cluster", "AWS::RedshiftServerless::Namespace", "AWS::DocDB::DBInstance", "AWS::DocDB::DBCluster", "AWS::DocDBElastic::Cluster"]

violation contains make_diag_full("pf-secretsmanager-target-attachment", "ERROR", name,
	"Properties.TargetType",
	sprintf("TargetType '%s' is not one of %s; the resource handler cannot read connection details for it", [t, concat(", ", _pf_smta_types)]),
	_pf_smta_fix, _pf_smta_url) if {
	some name in resources_of_type("AWS::SecretsManager::SecretTargetAttachment")
	t := resolve(name, "Properties.TargetType")
	is_string(t)
	not t in _pf_smta_types
}

_pf_smta_secret(name) := s if {
	s := resolve(name, "Properties.SecretId")
	s in resources_of_type("AWS::SecretsManager::Secret")
}

violation contains make_diag_full("pf-secretsmanager-target-attachment", "ERROR", name,
	"Properties.SecretId",
	sprintf("secret '%s' generates a bare password (GenerateSecretString without SecretStringTemplate), so the attachment has no JSON to merge connection details into; the resource handler fails with \"Failed to parse secret string while CREATE\"", [s]),
	_pf_smta_fix, _pf_smta_url) if {
	some name in resources_of_type("AWS::SecretsManager::SecretTargetAttachment")
	s := _pf_smta_secret(name)
	g := object.get(input.resources[s].properties, "GenerateSecretString", null)
	is_object(g)
	object.get(g, "SecretStringTemplate", "") == ""
}

violation contains make_diag_full("pf-secretsmanager-target-attachment", "ERROR", name,
	"Properties.SecretId",
	sprintf("secret '%s' has a SecretString that is not a JSON object, so the attachment cannot merge connection details into it; the resource handler fails with \"Failed to parse secret string while CREATE\"", [s]),
	_pf_smta_fix, _pf_smta_url) if {
	some name in resources_of_type("AWS::SecretsManager::SecretTargetAttachment")
	s := _pf_smta_secret(name)
	v := resolve(s, "Properties.SecretString")
	is_string(v)
	not _pf_smta_jsonobj(v)
}

_pf_smta_jsonobj(v) if {
	json.is_valid(v)
	is_object(json.unmarshal(v))
}
