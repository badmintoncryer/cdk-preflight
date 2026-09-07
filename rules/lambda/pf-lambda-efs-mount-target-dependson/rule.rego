package cdk_preflight

import rego.v1

_pf_lemtd_fix := "Add DependsOn for the AWS::EFS::MountTarget resources"

_pf_lemtd_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-function.html"

violation contains make_diag_full("pf-lambda-efs-mount-target-dependson", "ERROR", name,
	"DependsOn",
	sprintf("a function that mounts EFS without DependsOn on the mount target %v declared in the same template; CloudFormation cannot infer the order from the access point reference and creates the function before the mount target is available", [mt]),
	_pf_lemtd_fix, _pf_lemtd_url) if {
	some name in _pf_lam_fn
	_pf_lam_has(name, "FileSystemConfigs")
	some mt in resources_of_type("AWS::EFS::MountTarget")
	deps := object.get(input.resources[name], "dependsOn", [])
	not mt in deps
}
