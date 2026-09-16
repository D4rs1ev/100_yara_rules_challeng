rule Nable_Agent_Config_Malicious
{
    meta:
        date = "09-16-2026"
        author = "D4rs1ev"
        description = "N-able Agent config with attacker C2 / USERKEY"
    strings:
        $ini_header  = "[GENERAL]" ascii
        $srv         = "SERVER1=https://upload" ascii
        $c2_domain   = "am.remote.management" ascii
        $username    = "USERNAME=info@sweeds.net" ascii
        $userkey     = "USERKEY=dkmgncafocdpiinlelobpopklicjmglleoappechhgcghllkkfimndpbonlpljdnddpjlbggmnlcbcclbaemedfgcbccgpebniefdcmlajgphgebnndbonbfhlmghkp" ascii
        $agentmode   = "AGENTMODE=" ascii

    condition:
        $ini_header and
        ($srv or $c2_domain) and
        ($username or $userkey)
}