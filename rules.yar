rule EICAR_Test_File {
    meta:
        description = "EICAR Standard Antivirus Test File"
        severity = "High"
    strings:
        $a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $a
}

rule Suspicious_CMD_Command {
    meta:
        description = "Suspicious CMD command line deletion command"
        severity = "Medium"
    strings:
        $cmd = "cmd.exe" nocase
        $del = "/c del" nocase
    condition:
        $cmd and $del
}
