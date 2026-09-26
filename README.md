# Open Vehicle Threat Model & Logic Specification (OVTM-S)

## Abstract
This specification establishes a formal logic framework for auditing operational cyber-physical risks in networked vehicle architectures. It models domain boundaries, control flows, and remote code execution (RCE) surfaces to distinguish between logical software boundaries and hardware-enforced physical air-gaps.

---

## 1. System Formal Logic Axioms

### Axiom 1: Non-Zero Remote Execution Risk
For any vehicle system node $N$ exposed to an external network protocol $P$, the probability of an unintended physical state transition $S_{err}$ via an exploit chain $E$ is non-zero:
$$\forall N \in P, \quad P(S_{err} \mid E) > 0$$

### Axiom 2: Insufficiency of Logical Isolation
A software gateway or logical domain controller $G_{soft}$ operating between an untrusted network node $N_{untrusted}$ and a critical drive controller $C_{drive}$ does not constitute an air-gap ($AG$):
$$G_{soft}(N_{untrusted} \to C_{drive}) \neq AG$$

### Axiom 3: Cryptographic Key Non-Repudiation Limitation
Cryptographic verification $V_{crypto}$ validates payload authenticity, not execution safety $S_{safe}$. Valid signature $K_{valid}$ does not guarantee absence of malicious logic $L_{malicious}$:
$$V_{crypto}(K_{valid}) \nRightarrow S_{safe}(L_{malicious})$$

---

## 2. Architectural Threat Matrix

| Domain Vector | Execution Path | Isolation Mechanism | Systemic Risk Level |
| :--- | :--- | :--- | :--- |
| **Infotainment / Telematics** | Cellular / Wi-Fi / Bluetooth $\to$ User Space | Software Sandbox / Container | High Data Leakage / Low Kinetic Risk |
| **OTA Firmware Pipeline** | Cloud Infrastructure $\to$ System Flasher | Cryptographic Key Verification | Systemic Fleet Immobilization |
| **Drive-By-Wire Gateway** | Telematics RCE $\to$ CAN Bus Injection | Logical Domain Controller | **Catastrophic Kinetic Failure** |
| **Hardware Data Diode** | Unidirectional Optical Link | **Physical Air-Gap** | **Zero Remote Execution Risk** |

---

## 3. Automated Architecture Verification (Python Reference Implementation)

```python
from enum import Enum
from typing import List

class SafetyLevel(Enum):
    COMPROMISED = 0
    LOGICALLY_ISOLATED = 1
    HARDWARE_AIRGAPPED = 2

class VehicleNode:
    def __init__(self, node_id: str, is_network_facing: bool, controls_kinetic_systems: bool):
        self.node_id = node_id
        self.is_network_facing = is_network_facing
        self.controls_kinetic_systems = controls_kinetic_systems
        self.downstream_nodes: List['VehicleNode'] = []
        self.has_physical_data_diode: bool = False

    def add_downstream_target(self, target_node: 'VehicleNode', physical_diode: bool = False):
        self.downstream_nodes.append(target_node)
        if physical_diode:
            target_node.has_physical_data_diode = True

def audit_architecture_safety(nodes: List[VehicleNode]) -> SafetyLevel:
    for node in nodes:
        if node.is_network_facing:
            for target in node.downstream_nodes:
                if target.controls_kinetic_systems and not target.has_physical_data_diode:
                    print(f"[ALERT] Logical path exists between internet node '{node.node_id}' "
                          f"and kinetic node '{target.node_id}' without a hardware data diode!")
                    return SafetyLevel.COMPROMISED
    return SafetyLevel.HARDWARE_AIRGAPPED

# Example Test Case
if __name__ == "__main__":
    telematics = VehicleNode("Telematics_Unit", is_network_facing=True, controls_kinetic_systems=False)
    brakes = VehicleNode("Brake_ECU", is_network_facing=False, controls_kinetic_systems=True)
    
    # Simulating standard modern vehicle architecture (Logical Gateway Only)
    telematics.add_downstream_target(brakes, physical_diode=False)
    
    status = audit_architecture_safety([telematics, brakes])
    print(f"System Audit Result: {status.name}")
```

---

## 4. Policy vs. Engineering Compliance Engine

```
[INPUT: Regulatory Ban on Foreign Software]
       │
       ▼
[CHECK: Does vehicle retain cellular telemetry?] ──(YES)──► [RESULT: Vulnerability Retained]
       │
       (NO)
       ▼
[CHECK: Is operational domain hardware air-gapped?] ──(NO)──►  [RESULT: Vulnerability Retained]
       │
       (YES)
       ▼
[RESULT: Structural Safety Achieved]
```
```
