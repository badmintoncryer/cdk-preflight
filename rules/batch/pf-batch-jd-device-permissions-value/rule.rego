package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-device-permissions-value", "ERROR", name,
	"Properties.ContainerProperties.LinuxParameters.Devices",
	sprintf("%v is not a device permission (\"Invalid permission: %v for device %v\")", [p, p, object.get(d.value, "HostPath", "")]),
	"Use READ, WRITE or MKNOD",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_Device.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some d in flatten_list(name, "Properties.ContainerProperties.LinuxParameters.Devices")
	some p in object.get(d.value, "Permissions", [])
	_pf_batch_lit(p)
	not p in {"READ", "WRITE", "MKNOD"}
}
