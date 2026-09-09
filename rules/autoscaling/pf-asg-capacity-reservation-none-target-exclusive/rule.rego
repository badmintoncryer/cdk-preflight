package cdk_preflight

import rego.v1

_pf_asgcrn_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-capacity-reservation-none-target-exclusive", "ERROR", name,
	"Properties.CapacityReservationSpecification.CapacityReservationTarget",
	sprintf("CapacityReservationPreference is %s, which never targets a reservation, yet CapacityReservationTarget is set; the group create fails with \"You can't specify CapacityReservationPreference as default or none and provide a CapacityReservationTarget in the same request\"", [p]),
	"Set CapacityReservationPreference to capacity-reservations-only, or drop CapacityReservationTarget", _pf_asgcrn_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	p := resolve(name, "Properties.CapacityReservationSpecification.CapacityReservationPreference")
	p in ["none", "default"]
	not _pf_aslib_absent_at(name, ["CapacityReservationSpecification", "CapacityReservationTarget"])
}
