/*
 * Category: persistence
 * Purpose:  Flag references to common boot/init persistence locations
 *           used to survive firmware reboots.
 * Status:   Placeholder - expand with real indicators before relying on it.
 */

rule Init_Script_Persistence_Reference
{
    meta:
        description = "Firmware references an init.d/rc.local style persistence path"
        severity = "medium"
        author = "HexWarden"

    strings:
        $init_d = "/etc/init.d/" ascii
        $rc_local = "rc.local" ascii

    condition:
        any of them
}
