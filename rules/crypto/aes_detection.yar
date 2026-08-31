/*
 * Category: crypto
 * Purpose:  Flag the presence of the AES forward S-box constant table,
 *           which indicates a custom/embedded AES implementation.
 * Status:   Placeholder - expand with real indicators before relying on it.
 */

rule AES_SBox_Constant
{
    meta:
        description = "Firmware contains the AES forward S-box lookup table"
        severity = "medium"
        author = "HexWarden"

    strings:
        $aes_sbox = {
            63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
            CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0
        }

    condition:
        $aes_sbox
}
