---
title: "Steel Mountain - ICS Challenge"
date: 2026-02-26 00:01:00 +0000
categories: [HTB-Challenges]
tags: [ics, bacnet, industrial, scada, building-automation]
---

## Overview

This challenge simulates infiltrating a secure corporate facility's Building Automation and Control (BACnet) network to sabotage data storage infrastructure by triggering thermal destruction of backup tapes.

## Challenge Scenario

The objective involves manipulating a BACnet-enabled Industrial Control System serving "Steel Mountain," a facility with connections to major corporations. The attack strategy centers on exploiting environmental control mechanisms to overheat and destroy physical backup storage.

## BACnet Objects and Infrastructure

The system utilizes multiple object types for facility management:

**Sensor & Control Objects:**
- Analog Inputs (IDs 10, 20, 30): Temperature monitoring
- Analog Outputs (IDs 11-13, 21-23, 31-33): Thermostat and alarm control
- Binary Inputs (IDs 14, 24, 34): Alarm status indicators
- Binary Outputs (IDs 12, 22, 32, 500): AC units and messaging
- Multi-State Outputs (IDs 101-103): Door/lock mechanisms
- Multi-State Inputs (IDs 201, 202): Air handling units

## Exploitation Methodology

### Phase 1: Safety Mechanism Bypass
Raises overheat alarm thresholds to 60°C, preventing automated emergency responses during the heating sequence.

### Phase 2: Physical Containment
Secures the tape storage room (state 2) and seals lobby and server room entries (state 0) to isolate the target environment.

### Phase 3: Cooling System Shutdown
Disables all AC units by setting binary outputs to offline status (0).

### Phase 4: Heat Generation Maximization
Activates emergency heating modes across air handling units and raises thermostat setpoints to 45-50°C.

### Phase 5: Temperature Monitoring
Continuously tracks analog input sensors until the target area reaches the destruction threshold (35.0°C).

### Phase 6: Sabotage Completion
Triggers the message object to simulate tape destruction and retrieves the encoded flag from the system's description property.

## Key Vulnerabilities Identified

- **Insufficient Protocol Security:** BACnet often lacks inherent encryption or strong authentication.
- **Unsafe Write Permissions:** Safety-critical setpoints lack adequate access controls.
- **Physical-Digital Convergence Risks:** Direct translation of digital commands into destructive physical outcomes.

## Defensive Recommendations

Organizations operating BACnet systems should implement network segmentation, enforce authentication mechanisms, monitor setpoint modifications, and establish physical safeguards against unauthorized thermal manipulation.
