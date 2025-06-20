# make_server_proxy_def.ps1
# Generiert server_proxy.def aus server.dll, entfernt FUN_100011d0 und FUN_10003720

$dll = "server.dll"
$out = "server_proxy.def"

# 1) Header
"LIBRARY `"$dll`"" | Out-File $out -Encoding ASCII
"EXPORTS"                 | Out-File $out -Encoding ASCII -Append

# 2) Alle Exporte aus dumpbin einlesen
$d = & dumpbin /EXPORTS $dll

# 3) Zeilen extrahieren, die Ordinal und Namen enthalten
#    Format:    ordinal hint RVA name
$d | ForEach-Object {
    if ($_ -match '^\s+\d+') {
        # Spalte 4 ist der Name
        $parts = -split $_
        $name  = $parts[3]
        # Entferne die beiden gehookten
        if ($name -notin 'FUN_100011d0','FUN_10003720') {
            $name
        }
    }
} | Get-Unique | ForEach-Object {
    $_ | Out-File $out -Encoding ASCII -Append
}

Write-Host ">>> Generated $out with exports from $dll (minus hooks)"