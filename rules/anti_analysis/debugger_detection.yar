/*
 * Category: anti_analysis
 * Purpose:  Flag strings/symbols associated with anti-debugging or
 *           sandbox/emulator evasion techniques.
 * Status:   Placeholder - expand with real indicators before relying on it.
 */

rule Ptrace_AntiDebug_Reference
{
    meta:
        description = "Firmware references ptrace, commonly used for anti-debugging"
        severity = "medium"
        author = "HexWarden"

    strings:
        $ptrace = "ptrace" ascii

    condition:
        $ptrace
}
