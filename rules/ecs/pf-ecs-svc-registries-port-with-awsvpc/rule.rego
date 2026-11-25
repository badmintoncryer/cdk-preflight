package cdk_preflight

import rego.v1

# The error is the answer for a registry that publishes only A/AAAA records. With an SRV
# record, ContainerName + ContainerPort (or Port) are required instead (#409; ECS API
# reference, ServiceRegistry). So the rule only speaks when the registry is a discovery
# service in this template whose DnsRecords are literal and carry no SRV entry; a registry
# it cannot trace stays silent.
violation contains make_diag_full("pf-ecs-svc-registries-port-with-awsvpc", "ERROR", name,
	"Properties.ServiceRegistries",
	"An awsvpc service sets ContainerName / ContainerPort on a service registry without SRV records; CreateService fails with \"The values specified for serviceRegistries do not require a value for 'containerPort'\"",
	"Drop ContainerName and ContainerPort, or give the discovery service an SRV record",
	"https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_ServiceRegistry.html") if {
	some name in resources_of_type("AWS::ECS::Service")
	_pf_ecs_has(name, "NetworkConfiguration")
	some sr in flatten_list(name, "Properties.ServiceRegistries")
	some k in {"ContainerName", "ContainerPort"}
	_pf_ecs_ohas(sr.value, k)
	reg := resolve(name, sprintf("Properties.ServiceRegistries.%d.RegistryArn", [sr.index]))
	reg in resources_of_type("AWS::ServiceDiscovery::Service")
	recs := resolve(reg, "Properties.DnsConfig.DnsRecords")
	is_array(recs)
	count(recs) > 0
	every r in recs {
		is_object(r)
		is_string(object.get(r, "Type", null))
		r.Type != "SRV"
	}
}
