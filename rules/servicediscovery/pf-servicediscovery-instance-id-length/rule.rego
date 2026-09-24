package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-servicediscovery-instance-id-length", "ERROR", name,
	"Properties.InstanceId",
	sprintf("InstanceId is %d characters; the registration fails with \"Value at 'instanceId' failed to satisfy constraint: Member must have length less than or equal to 64\"", [count(iid)]),
	"Use an instance id of at most 64 characters",
	"https://docs.aws.amazon.com/cloud-map/latest/api/API_RegisterInstance.html") if {
	some name in resources_of_type("AWS::ServiceDiscovery::Instance")
	iid := resolve(name, "Properties.InstanceId")
	is_string(iid)
	not input.resources[iid]
	count(iid) > 64
}
