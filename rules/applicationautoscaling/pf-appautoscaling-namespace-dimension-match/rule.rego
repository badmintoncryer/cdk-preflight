package cdk_preflight

import rego.v1

# All 24 ScalableDimension values start with the ServiceNamespace they belong to.
# A pair that disagrees names no scalable target, and RegisterScalableTarget
# rejects it. Only fires when both sides are real namespaces, so a typo'd
# namespace or dimension stays one problem and not two.
violation contains make_diag_full("pf-appautoscaling-namespace-dimension-match", "ERROR", name,
	"Properties.ScalableDimension",
	sprintf("ScalableDimension '%s' belongs to the '%s' namespace but ServiceNamespace is '%s'; RegisterScalableTarget rejects the pair", [dim, head, ns]),
	"Use the ScalableDimension whose first segment is the ServiceNamespace (ServiceNamespace dynamodb goes with dynamodb:table:ReadCapacityUnits)",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_RegisterScalableTarget.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	ns := resolve(name, "Properties.ServiceNamespace")
	ns in _pf_aaslib_namespaces
	dim := resolve(name, "Properties.ScalableDimension")
	is_string(dim)
	head := split(dim, ":")[0]
	head in _pf_aaslib_namespaces
	head != ns
}
