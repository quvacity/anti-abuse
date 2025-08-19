rule CHINESE_NEZHA_ARGO {
    strings:
        $a1 = "TkVaSEE=" // Base64 for "NEZHA"
        $a2 = "tunnel.json"
        $a3 = "vless"
        $a4 = "dmxlc3M=" // Base64 for "vless"
        $a5 = "vmess"
        $a6 = "L3ZtZXNz" // Base64 for "/vmess"
        $a7 = "V0FSUA==" // Base64 for "WARP"
        $a8 = "/eooce/"
        $a9 = "ARGO_AUTH"
        $a10 = "--edge-ip-version"
        $a11 = "LS1lZGdlLWlwLXZlcnNpb24=" // Base64 for "--edge-ip-version"
        $a12 = "sub.txt"
        $a13 = "Server\x20is\x20running\x20on\x20port\x20"
        $a14 = "hysteria2"
        $a15 = "openssl req"
        $a16 = "hysteria2"
        $a17 = "NEZHA" nocase
        $a18 = "babama1001980"
        $a19 = "ARGO_AUTH"
        $a20 = "HY2_PORT"
        $a21 = "ssss.nyc.mn"
        $a22 = "using this script,"
        $a23 = "__import__('zlib').decompress"
        
    condition:
        2 of ($a*)
}

rule JS_OBFUSCATED_CODE {
    strings:
        $f1 = "0x" nocase
        $f2 = "x20" nocase
        $f3 = "x0a" nocase
        $f4 = "{" nocase
    condition:
        4 of ($f1, $f2, $f3, $f4)
}

rule PY_OBFUSCATED_CODE {
    strings:
        $f1 = "freecodingtools.org" nocase
        $f2 = "__import__('zlib').decompress" nocase
        $f3 = "__[::-1]" nocase
    condition:
        3 of ($f1, $f2, $f3)
}

rule OVERLOAD_CRYPTO_MINER {
    meta:
        ref = "https://gist.github.com/GelosSnake/c2d4d6ef6f93ccb7d3afb5b1e26c7b4e"
    strings:
        $a1 = "stratum+tcp"
        $a2 = "xmrig"
        $a3 = "crypto"

    condition:
        2 of them
}

rule REVERSE_SHELL {
    strings:
        $a1 = "0>&1"
        $a2 = "sh"
        $a3 = "-i"
        $a4 = "0<&196"
        $a5 = "<>/dev/tcp"
        $a6 = "socket.socket"

    condition:
        3 of them
}

rule xdearboy_PTERO_CRASHER {
    strings:
        $a1 = "fallocate"
        $a2 = "java.util.concurrent.Executors"
        $a3 = "___tmp_"
        $a4 = "ScheduledExecutorService"

    condition:
        3 of them
}
