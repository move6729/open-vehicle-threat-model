"""
OVTM-S v1.1 Architecture Verification Engine
Evaluates hardware isolation invariants across vehicle network node trees.
"""

from enum import Enum
from typing import List, Optional

class IsolationLevel(Enum):
    COMPROMISED_LOGICAL_GATEWAY = 0
    PARTIALLY_ISOLATED = 1
    HARDWARE_ENFORCED_AIRGAP = 2

class ControlDomain(Enum):
    TELEMATICS_EXTERNAL = 0
    BODY_COMFORT = 1
    KINETIC_DRIVE_BY_WIRE = 2

class VehicleNode:
    def __init__(self, node_id: str, domain: ControlDomain, is_network_facing: bool):
        self.node_id = node_id
        self.domain = domain
        self.is_network_facing = is_network_facing
        self.downstream_nodes: List['VehicleNode'] = []
        self.has_hardware_interlock: bool = False

    def add_downstream_target(self, target_node: 'VehicleNode', hardware_interlock: bool = False):
        self.downstream_nodes.append(target_node)
        if hardware_interlock:
            target_node.has_hardware_interlock = True

def audit_kinetic_isolation(nodes: List[VehicleNode]) -> IsolationLevel:
    """
    Traverses graph node paths from network-facing interfaces to kinetic actuators.
    Enforces Invariant 2: Logical gateways return COMPROMISED status.
    """
    for node in nodes:
        if node.is_network_facing:
            for target in node.downstream_nodes:
                if target.domain == ControlDomain.KINETIC_DRIVE_BY_WIRE and not target.has_hardware_interlock:
                    print(f"[FAIL] Invariant 2 Violation: Path from network node '{node.node_id}' "
                          f"to kinetic domain node '{target.node_id}' relies on logical isolation.")
                    return IsolationLevel.COMPROMISED_LOGICAL_GATEWAY
                    
    return IsolationLevel.HARDWARE_ENFORCED_AIRGAP

if __name__ == "__main__":
    # Test Architecture Execution
    tcu = VehicleNode("TCU_Cellular", ControlDomain.TELEMATICS_EXTERNAL, is_network_facing=True)
    vcu = VehicleNode("VCU_Braking", ControlDomain.KINETIC_DRIVE_BY_WIRE, is_network_facing=False)
    
    # Simulate Vulnerable Logical Boundary (Standard Legacy Architecture)
    tcu.add_downstream_target(vcu, hardware_interlock=False)
    audit_result = audit_kinetic_isolation([tcu, vcu])
    print(f"Audit Status: {audit_result.name}\n")
    
    # Simulate Hardware-Enforced Interlock Boundary
    vcu.has_hardware_interlock = True
    audit_result_secure = audit_kinetic_isolation([tcu, vcu])
    print(f"Hardened Audit Status: {audit_result_secure.name}")
