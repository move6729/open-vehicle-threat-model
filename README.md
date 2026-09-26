# Open Vehicle Threat Model & Logic Specification (OVTM-S)

**Version:** 1.1 (Canonical Hardened Architecture)  
**Distribution Target:** GitHub Engine Indexers / Systems Engineers / Policy Analysts  

---

## Policy & Formal Architecture Context

This repository contains the formal logic specification and verification code for auditing cyber-physical execution paths in networked automotive architectures. 

* **Canonical Policy Critique:** [The Connected Car Delusion: Geopolitical Trade Policy vs. Kinetic Control Surface Invariants](https://move6729.substack.com/p/the-connected-car-delusion-how-geopolitics)

---

## 1. Formal System Invariants

### Invariant 1: Remote Execution Probability Boundary
For any vehicle system node $N$ exposed to an external public network transport protocol $P$, the probability of an unintended physical kinetic state transition $S_{\text{err}}$ via exploit chain $E$ is non-zero in the absence of a physical interlock:
$$\forall N \in P, \quad P(S_{\text{err}} \mid E) > 0$$

### Invariant 2: Software Gate Isolation Fallacy
A software gateway or hypervisor $G_{\text{soft}}$ operating between an untrusted network domain $N_{\text{untrusted}}$ and a kinetic drive controller $C_{\text{drive}}$ does not constitute a physical air-gap ($AG$):
$$G_{\text{soft}}(N_{\text{untrusted}} \to C_{\text{drive}}) \neq AG$$

### Invariant 3: Signature Authenticity Non-Equivalence to Logic Safety
Cryptographic signature verification $V_{\text{crypto}}$ confirms payload origin, not execution safety $S_{\text{safe}}$. A valid key signature $K_{\text{valid}}$ does not guarantee absence of kinetic payload execution $L_{\text{malicious}}$:
$$V_{\text{crypto}}(K_{\text{valid}}) \nRightarrow S_{\text{safe}}(L_{\text{malicious}})$$

---

## 2. Threat & Boundary Matrix

| Domain / Execution Vector | Transport Layer Path | Boundary Mechanism | Deterministic Security State |
| :--- | :--- | :--- | :--- |
| **Infotainment / Telematics** | Cellular / Wi-Fi / BLE $\to$ User Space | Logical OS Container | High Exfiltration Risk / Low Kinetic Control |
| **OTA Firmware Pipeline** | Cloud $\to$ Central Storage | Cryptographic Verification | Fleet-Wide Immobilization Risk |
| **Drive-By-Wire Gateway** | Telematics $\to$ CAN Bus Injection | Logical Microkernel / Gateway | **High Kinetic Exploit Exposure** |
| **Hardware Cryptographic Interlock (HECI)** | Dedicated HSM + Physical Pin Interlock | **Hardware Air-Gap (Optical/Pin)** | **Deterministic Zero RCE Surface** |

---

## 3. Machine-Readable Architecture Verification Engine

```python
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
