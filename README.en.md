# FSD interception environment

[简体中文](README.md)

This Windows project is designed to intercept a Tesla vehicle’s requests for feature settings and return a replacement configuration with Full Self-Driving (FSD) flags enabled. It includes PowerShell scripts, Python services, and a browser-based status dashboard.

## Reading the project

The Chinese documentation uses `车机` for the vehicle’s onboard computer, `热点` for a Wi-Fi hotspot, and `看板` for the status dashboard. FSD refers to Tesla’s Full Self-Driving driver-assistance features.

## Compatibility

### Target for Tesla software 2026.44.1 (unverified)

The goal is for the dashboard to read a sanitized, offline configuration sample labeled 2026.44.1, display recognized fields, and show missing or unrecognized states as “Unknown.” Record the sample source, software version, and observed dashboard output during verification. This target covers offline display only. Vehicle compatibility remains unverified.

An enabled flag in a configuration response does not establish that a vehicle supports a feature or that the feature is available in a given market. Compatibility across vehicle models, software versions, Windows display languages, and regions has not been verified for this English overview.
