/*
 * Category: network
 * Purpose:  Flag hardcoded network indicators commonly seen in firmware
 *           implants (raw IP literals, suspicious URL schemes).
 * Status:   Placeholder - expand with real indicators before relying on it.
 */

rule Suspicious_Hardcoded_URL
{
    meta:
        description = "Firmware contains a hardcoded HTTP(S) URL"
        severity = "low"
        author = "HexWarden"

    strings:
        $http = "http://" ascii wide
        $https = "https://" ascii wide

    condition:
        any of them
}
