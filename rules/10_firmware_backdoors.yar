/*
    HexWarden — SIH1387
    10_firmware_backdoors.yar

    Vendor-agnostic implant heuristics for embedded Linux / RTOS firmware.
    These are the rules that carry the demo: they fire on the *shape* of a
    backdoor rather than on a hash of one specific sample.
*/

rule FW_Hardcoded_Root_Account
{
    meta:
        author      = "HexWarden"
        severity    = "high"
        category    = "backdoor_auth"
        description = "Shadow/passwd entry with a UID-0 account baked into firmware"
        why_it_matters = "Undocumented UID-0 account = permanent operator-invisible access"

    strings:
        // root-equivalent account lines in an embedded /etc/passwd
        $p1 = /[a-z_][a-z0-9_-]{0,15}:[^:\n]*:0:0:/ ascii
        // hashed creds shipped in the image
        $h1 = "$1$" ascii     // MD5-crypt
        $h2 = "$5$" ascii     // SHA-256-crypt
        $h3 = "$6$" ascii     // SHA-512-crypt
        $h4 = "$y$" ascii     // yescrypt

        $ctx1 = "/etc/passwd" ascii
        $ctx2 = "/etc/shadow" ascii
        $ctx3 = "root:" ascii

    condition:
        ($p1 and 1 of ($h*)) or (1 of ($h*) and 2 of ($ctx*))
}

rule FW_Undocumented_Support_Account
{
    meta:
        author      = "HexWarden"
        severity    = "critical"
        category    = "backdoor_auth"
        description = "Vendor 'service' style account names commonly used as maintenance backdoors"
        fp_note     = "Confirm against vendor documentation before calling it malicious"

    strings:
        $a1 = "factory:" ascii
        $a2 = "backdoor" nocase ascii wide
        $a3 = "debugadmin" nocase ascii
        $a4 = "supervisor:" nocase ascii
        $a5 = "remotesupport" nocase ascii
        $a6 = "maint:" nocase ascii
        $a7 = "vendor_service" nocase ascii

        $ctx = "/etc/passwd" ascii

    condition:
        (1 of ($a*) and $ctx) or 2 of ($a*)
}

rule FW_Hidden_Auth_Bypass_String
{
    meta:
        author      = "HexWarden"
        severity    = "critical"
        category    = "backdoor_auth"
        description = "Magic-string comparison near authentication routines"
        why_it_matters = "Classic 'if (strcmp(pw, MAGIC)==0) grant_root()' pattern"

    strings:
        $cmp1 = "strcmp" fullword ascii
        $cmp2 = "strncmp" fullword ascii
        $cmp3 = "memcmp" fullword ascii

        $auth1 = "login incorrect" nocase ascii
        $auth2 = "authenticate" nocase ascii
        $auth3 = "check_password" nocase ascii
        $auth4 = "pam_authenticate" ascii

        $magic1 = "letmein" nocase ascii
        $magic2 = "0penSesame" nocase ascii
        $magic3 = "xmhdipc" ascii            // seen in embedded default-cred lists
        $magic4 = "GM8182" ascii
        $magic5 = "superuser" nocase ascii

    condition:
        1 of ($cmp*) and 1 of ($auth*) and 1 of ($magic*)
}

rule FW_Reverse_Shell_Primitive
{
    meta:
        author      = "HexWarden"
        severity    = "critical"
        category    = "implant_c2"
        description = "Reverse shell / remote command execution primitives in firmware"

    strings:
        $rs1 = "/bin/sh -i" ascii
        $rs2 = "sh -c" ascii
        $rs3 = "nc -e" ascii
        $rs4 = "nc -l -p" ascii
        $rs5 = "mkfifo" fullword ascii
        $rs6 = "dup2" fullword ascii
        $rs7 = "/dev/tcp/" ascii
        $rs8 = "telnetd -l /bin/sh" ascii

        $dl1 = "wget http" nocase ascii
        $dl2 = "curl -s" ascii
        $dl3 = "tftp -g" ascii
        $dl4 = "| sh" ascii

    condition:
        3 of ($rs*) or (1 of ($rs*) and 2 of ($dl*)) or $rs7 or $rs8
}

rule FW_Hardcoded_C2_Endpoint
{
    meta:
        author      = "HexWarden"
        severity    = "high"
        category    = "implant_c2"
        description = "Hardcoded external IP or dynamic-DNS host inside firmware"
        why_it_matters = "Substation gear should never dial out to the internet"
        fp_note      = "Strip RFC1918, loopback, and vendor NTP/update hosts in post-processing"

    strings:
        $ip   = /([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}/ ascii
        $ddns1 = ".no-ip." nocase ascii
        $ddns2 = ".duckdns." nocase ascii
        $ddns3 = ".dyndns." nocase ascii
        $ddns4 = ".ddns.net" nocase ascii
        $onion = ".onion" nocase ascii

        $net1 = "connect" fullword ascii
        $net2 = "socket" fullword ascii

    condition:
        ($ip and 1 of ($net*)) or 1 of ($ddns*) or $onion
}

rule FW_Persistence_Startup_Hook
{
    meta:
        author      = "HexWarden"
        severity    = "medium"
        category    = "persistence"
        description = "Writes to init/cron paths — persistence across reboot"

    strings:
        $p1 = "/etc/init.d/" ascii
        $p2 = "/etc/rc.local" ascii
        $p3 = "/etc/crontab" ascii
        $p4 = "/etc/cron.d/" ascii
        $p5 = "/etc/rcS.d/" ascii
        $p6 = "inittab" fullword ascii

        $w1 = "fopen" fullword ascii
        $w2 = "chmod +x" ascii
        $w3 = "system" fullword ascii

    condition:
        2 of ($p*) and 1 of ($w*)
}

rule FW_Logic_Bomb_Time_Trigger
{
    meta:
        author      = "HexWarden"
        severity    = "high"
        category    = "logic_bomb"
        description = "Date/time comparison adjacent to destructive or control operations"
        why_it_matters = "Industroyer's payloads were time-scheduled; so was the Ukraine 2016 trip"

    strings:
        $t1 = "localtime" fullword ascii
        $t2 = "gmtime" fullword ascii
        $t3 = "mktime" fullword ascii
        $t4 = "tm_year" fullword ascii
        $t5 = "difftime" fullword ascii

        $d1 = "MEMORY_ERASE" nocase ascii
        $d2 = "flash_erase" nocase ascii
        $d3 = "mtd_erase" nocase ascii
        $d4 = "dd if=/dev/zero" ascii
        $d5 = "reboot" fullword ascii
        $d6 = "TRIP" fullword ascii wide
        $d7 = "OPEN_BREAKER" nocase ascii wide

    condition:
        2 of ($t*) and 1 of ($d*)
}

rule FW_AntiForensics_LogWipe
{
    meta:
        author      = "HexWarden"
        severity    = "high"
        category    = "anti_forensics"
        description = "Firmware code that clears event logs or syslog"
        why_it_matters = "SER/event logs are the operator's only view of what a relay did"

    strings:
        $l1 = "/var/log/" ascii
        $l2 = "syslog" fullword ascii
        $l3 = "wtmp" fullword ascii
        $l4 = "lastlog" fullword ascii
        $l5 = "event.log" nocase ascii
        $l6 = "sequence of events" nocase ascii wide

        $w1 = "unlink" fullword ascii
        $w2 = "remove" fullword ascii
        $w3 = "truncate" fullword ascii
        $w4 = "rm -rf" ascii
        $w5 = "> /dev/null" ascii

    condition:
        2 of ($l*) and 1 of ($w*)
}

rule FW_Debug_Interface_Left_Enabled
{
    meta:
        author      = "HexWarden"
        severity    = "medium"
        category    = "hardening"
        description = "Production firmware shipping with debug/console access enabled"
        fp_note     = "Very common in real devices — report as hygiene finding, not compromise"

    strings:
        $d1 = "console=ttyS0" ascii
        $d2 = "init=/bin/sh" ascii
        $d3 = "CONFIG_DEBUG" ascii
        $d4 = "dropbear" fullword ascii
        $d5 = "telnetd" fullword ascii
        $d6 = "gdbserver" fullword ascii
        $d7 = "jtag" nocase ascii

    condition:
        2 of them
}
