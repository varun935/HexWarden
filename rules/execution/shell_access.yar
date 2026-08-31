/*
 * Category: execution
 * Purpose:  Flag embedded shell/command-execution primitives that are
 *           unusual for constrained embedded firmware.
 * Status:   Placeholder - expand with real indicators before relying on it.
 */

rule Embedded_Shell_Reference
{
    meta:
        description = "Firmware references a shell binary or /bin/sh-style path"
        severity = "medium"
        author = "HexWarden"

    strings:
        $sh = "/bin/sh" ascii
        $bash = "/bin/bash" ascii
        $busybox = "busybox" ascii nocase

    condition:
        any of them
}
