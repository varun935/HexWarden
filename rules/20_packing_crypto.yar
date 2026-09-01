/*
    HexWarden — SIH1387
    20_packing_crypto.yar

    These pair directly with entropy_analysis. Entropy tells you "there is a
    high-randomness blob at offset X". These rules try to tell you *what* it is:
    a legitimate compressed rootfs, a packer, or an encrypted stage-2 payload.
*/

import "math"

rule PACK_UPX_Header
{
    meta:
        author      = "HexWarden"
        severity    = "medium"
        category    = "packing"
        description = "UPX-packed executable inside firmware"
        fp_note     = "Some vendors legitimately UPX their userland binaries to save flash"

    strings:
        $u1 = "UPX!" ascii
        $u2 = "UPX0" ascii
        $u3 = "UPX1" ascii
        $u4 = "$Info: This file is packed with the UPX" ascii

    condition:
        1 of them
}

rule PACK_Stripped_UPX
{
    meta:
        author      = "HexWarden"
        severity    = "high"
        category    = "packing"
        description = "UPX stub present but magic bytes removed — deliberate anti-analysis"
        why_it_matters = "Nobody strips UPX magic for legitimate reasons"

    strings:
        $stub1 = "$Id: UPX" ascii
        $stub2 = "PROT_EXEC|PROT_WRITE failed" ascii
        $magic = "UPX!" ascii

    condition:
        1 of ($stub*) and not $magic
}

rule CRYPTO_AES_SBox_Constants
{
    meta:
        author      = "HexWarden"
        severity    = "low"
        category    = "crypto"
        description = "AES S-box table present"
        fp_note     = "Ubiquitous — only interesting when it appears in a binary with no documented crypto need"

    strings:
        $sbox = { 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76 }
        $inv  = { 52 09 6a d5 30 36 a5 38 bf 40 a3 9e 81 f3 d7 fb }

    condition:
        1 of them
}

rule CRYPTO_Custom_XOR_Obfuscation
{
    meta:
        author      = "HexWarden"
        severity    = "medium"
        category    = "obfuscation"
        description = "String obfuscation helper alongside execution primitives"

    strings:
        $x1 = "xor_decrypt" nocase ascii
        $x2 = "deobfuscate" nocase ascii
        $x3 = "decode_string" nocase ascii
        $x4 = "unscramble" nocase ascii

        $e1 = "system" fullword ascii
        $e2 = "execve" fullword ascii
        $e3 = "dlopen" fullword ascii

    condition:
        1 of ($x*) and 1 of ($e*)
}

rule ENTROPY_High_Blob_No_Known_Format
{
    meta:
        author      = "HexWarden"
        severity    = "medium"
        category    = "entropy"
        description = "High-entropy region with no recognised compression/filesystem magic"
        why_it_matters = "Legit compression announces itself. Encrypted payloads do not."
        fp_note      = "Run only on carved segments, not the whole image"

    strings:
        // known, benign high-entropy container magics
        $gzip     = { 1f 8b 08 }
        $xz       = { fd 37 7a 58 5a 00 }
        $lzma     = { 5d 00 00 }
        $squashfs = "hsqs" ascii
        $squashbe = "sqsh" ascii
        $jffs2    = { 19 85 }
        $ubi      = "UBI#" ascii
        $cramfs   = { 45 3d cd 28 }
        $zip      = { 50 4b 03 04 }

    condition:
        filesize > 4KB
        and filesize < 32MB
        and math.entropy(0, filesize) >= 7.5
        and none of them
}

rule CERT_Embedded_Private_Key
{
    meta:
        author      = "HexWarden"
        severity    = "critical"
        category    = "secrets"
        description = "Private key material shipped inside firmware"
        why_it_matters = "One leaked key compromises every device on that fleet"

    strings:
        $k1 = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $k2 = "-----BEGIN PRIVATE KEY-----" ascii
        $k3 = "-----BEGIN EC PRIVATE KEY-----" ascii
        $k4 = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii
        $k5 = "-----BEGIN DSA PRIVATE KEY-----" ascii
        $k6 = "PuTTY-User-Key-File" ascii

    condition:
        1 of them
}

rule SECRET_Hardcoded_API_Token
{
    meta:
        author      = "HexWarden"
        severity    = "high"
        category    = "secrets"
        description = "Credential-shaped assignment inside firmware"

    strings:
        $a = /(api[_-]?key|secret[_-]?key|auth[_-]?token|passwd|password)\s*[:=]\s*["'][A-Za-z0-9+\/=_\-]{12,}["']/ nocase ascii

    condition:
        $a
}
