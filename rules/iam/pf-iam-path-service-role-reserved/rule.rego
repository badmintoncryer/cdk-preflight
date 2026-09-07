package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-path-service-role-reserved", "ERROR", name,
	"Properties.Path",
	sprintf("Path '%s' is under /aws-service-role, which IAM reserves for service-linked roles: creation fails with \"Paths beginning with '/aws-service-role' are reserved for AWS Service Linked Roles\"", [v]),
	"Pick any other path (/service-role/ is the conventional one for roles a service assumes), or create the entity as AWS::IAM::ServiceLinkedRole",
	"https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-service.html") if {
	some t in {"AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Group", "AWS::IAM::InstanceProfile", "AWS::IAM::ManagedPolicy"}
	some name in resources_of_type(t)
	v := resolve(name, "Properties.Path")
	is_string(v)
	startswith(v, "/aws-service-role")
}
