package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-instance-id-pattern", "ERROR", name,
	"Properties.InstanceId",
	sprintf("InstanceId '%v' has characters outside ^[0-9a-zA-Z_/:.@-]+$; the registration fails with \"Value at 'instanceId' failed to satisfy constraint: Member must satisfy regular expression pattern: ^[0-9a-zA-Z_/:.@-]+$\"", [iid]),
	"Use only letters, digits and _ / : . @ - in the instance id",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	iid := resolve(name, "Properties.InstanceId")
	is_string(iid)
	not input.resources[iid]
	not regex.match(`^[0-9a-zA-Z_/:.@-]+$`, iid)
}
