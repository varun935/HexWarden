/*
    HexWarden — SIH1387
    00_ics_protocols.yar

    These rules do NOT mean "malware". They mean "this binary knows how to
    speak to grid equipment". That is normal in an RTU or gateway and very
    abnormal in, say, a temperature sensor or an HMI splash-screen binary.

    The scoring layer (correlator.py) should treat these as CONTEXT that
    amplifies other findings, not as standalone verdicts.
*/

rule ICS_IEC104_Stack
{
    meta:
        author       = "HexWarden"
        severity     = "medium"
        category     = "ics_protocol"
        protocol     = "IEC 60870-5-104"
        description  = "Binary contains IEC-104 telecontrol protocol handling"
        why_it_matters = "104 carries breaker open/close commands over TCP/2404"
        fp_note      = "Legitimate in RTUs and substation gateways"

    strings:
        $n1 = "IEC104" nocase ascii wide
        $n2 = "IEC-104" nocase ascii wide
        $n3 = "60870-5-104" ascii wide
        $n4 = "iec60870" nocase ascii wide

        // ASDU type identifiers — these are the actual command primitives
        $a1 = "C_SC_NA_1" ascii wide      // single command  (breaker)
        $a2 = "C_DC_NA_1" ascii wide      // double command  (breaker)
        $a3 = "C_RC_NA_1" ascii wide      // regulating step command
        $a4 = "M_SP_NA_1" ascii wide      // single point info
        $a5 = "C_IC_NA_1" ascii wide      // interrogation

        $p  = "2404" fullword ascii

    condition:
        2 of ($n*) or 2 of ($a*) or ($p and 1 of ($n*, $a*))
}

rule ICS_IEC61850_MMS_GOOSE
{
    meta:
        author       = "HexWarden"
        severity     = "medium"
        category     = "ics_protocol"
        protocol     = "IEC 61850"
        description  = "Binary contains IEC 61850 MMS/GOOSE substation bus handling"
        why_it_matters = "GOOSE is the fast trip bus between protection relays"
        fp_note      = "Expected in modern IEDs and bay controllers"

    strings:
        $s1 = "61850" ascii wide
        $s2 = "GOOSE" fullword ascii wide
        $s3 = "goosePdu" ascii wide
        $s4 = "MMS" fullword ascii wide
        $s5 = "gocbRef" ascii wide
        $s6 = "datSet" fullword ascii wide
        $s7 = "stNum" fullword ascii wide
        $s8 = "sqNum" fullword ascii wide
        $s9 = "IEC61850" nocase ascii wide

        $p  = "102" fullword ascii     // MMS over TCP/102

    condition:
        3 of ($s*) or ($p and 2 of ($s*))
}

rule ICS_DNP3_Stack
{
    meta:
        author       = "HexWarden"
        severity     = "medium"
        category     = "ics_protocol"
        protocol     = "DNP3"
        description  = "Binary contains DNP3 outstation/master handling"
        fp_note      = "Common in North-American-market RTUs"

    strings:
        $s1 = "DNP3" nocase ascii wide
        $s2 = "dnp3" ascii wide
        $s3 = "outstation" nocase ascii wide
        $s4 = "CROB" fullword ascii wide          // control relay output block
        $s5 = "LATCH_ON" ascii wide
        $s6 = "PULSE_ON" ascii wide
        $p  = "20000" fullword ascii              // TCP/20000

    condition:
        2 of ($s*) or ($p and 1 of ($s*))
}

rule ICS_Modbus_Stack
{
    meta:
        author       = "HexWarden"
        severity     = "low"
        category     = "ics_protocol"
        protocol     = "Modbus"
        description  = "Binary contains Modbus TCP/RTU handling"
        fp_note      = "Extremely common; low signal on its own"

    strings:
        $s1 = "modbus" nocase ascii wide
        $s2 = "MBAP" fullword ascii wide
        $s3 = "WriteMultipleCoils" nocase ascii wide
        $s4 = "WriteSingleRegister" nocase ascii wide
        $s5 = "IllegalDataAddress" nocase ascii wide
        $p  = "502" fullword ascii

    condition:
        2 of ($s*) or ($p and 1 of ($s*))
}

rule ICS_Protocol_In_Unexpected_Binary
{
    meta:
        author       = "HexWarden"
        severity     = "high"
        category     = "ics_protocol"
        description  = "Grid protocol strings co-located with network C2 primitives"
        why_it_matters = "A protocol stack that also builds outbound sockets to a hardcoded host is the Industroyer shape"

    strings:
        $ics1 = "IEC104" nocase ascii wide
        $ics2 = "60870" ascii wide
        $ics3 = "61850" ascii wide
        $ics4 = "GOOSE" fullword ascii wide
        $ics5 = "DNP3" nocase ascii wide

        $net1 = "connect" fullword ascii
        $net2 = "socket" fullword ascii
        $net3 = "inet_addr" fullword ascii
        $net4 = "gethostbyname" fullword ascii

        $exec1 = "/bin/sh" ascii
        $exec2 = "system" fullword ascii
        $exec3 = "popen" fullword ascii

    condition:
        1 of ($ics*) and 2 of ($net*) and 1 of ($exec*)
}
