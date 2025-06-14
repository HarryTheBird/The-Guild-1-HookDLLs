Proxy-DLL & Timeout-Fix für server.dll

Dieses Repository enthält zwei Proxy-DLLs, mit denen Du die originale server.dll eines Multiplayer-Servers erweitern kannst, um:

Winsock-Blockierungen und Paketabbrüche mit einer Sequenz-/Ack- und CRC-basierten Retry-Logik (ws2_32.dll)

Interne Timeout-Prüfungen in FUN_10009AC0 kontext-sensitiv zu unterdrücken (kernel32.dll)

Beide Proxy-DLLs werden vom Windows-Loader automatisch geladen, wenn sie neben der Original-server.dll liegen.

📂 Projektstruktur

hook-project/
├── .vscode/                  # VS Code Konfigurationen
│   ├── tasks.json            # Build-Tasks für beide DLLs
│   ├── c_cpp_properties.json # IntelliSense-Einstellungen
│   └── launch.json           # Debug-Konfiguration (optional)
├── include/                  # (optional) zusätzliche Header
├── src/                      # Quellcode
│   ├── ws2_32_proxy.c        # Winsock-Proxy mit Sequenz/Ack/CRC
│   └── kernel32_proxy.c      # Kernel32-Proxy mit Timeout-Hook
├── ws2_32.def                # Export-Map für winsock-Proxy
├── kernel32.def              # Export-Map für kernel32-Proxy
└── bin/                      # Output-Verzeichnis (gebaute DLLs)

🛠️ Funktionsweise der Hook-DLLs

1. ws2_32.dll Proxy

recv liest Header (4-Byte CRC32) + Payload in einen temporären Puffer.

Ruft die originale FUN_100011D0 aus server.dll auf, um CRC32 über den Payload zu berechnen.

Bei CRC-Mismatch oder unvollständigem Empfang wird rekursiv ein neuer recv gestartet.

Bei Erfolg wird der reine Payload in den übergebenen Buffer kopiert.

send fügt vor jedem Paket eine 4-Byte Sequenznummer (netto) hinzu, sendet Header+Payload und wartet auf ein 4-Byte Ack.

Retry-Loop bei WSAEWOULDBLOCK oder NACK, bis das richtige Ack empfangen wird.

So wird sichergestellt, dass nur vollständige, geprüfte Pakete in die interne Logik der server.dll gelangen.

2. kernel32.dll Proxy

Hook auf GetTickCount und GetTickCount64:

Ermittelt per RtlCaptureContext die Rücksprungadresse.

Wenn der Aufruf aus FUN_10009AC0 (RVA-basiert) stammt, gibt der Hook immer 0 zurück → interne Timeouts werden deaktiviert.

In allen anderen Fällen wird die originale Funktion aufgerufen.

So bleibt der System-Timer für alle anderen Komponenten unverändert und nur der kritische Timeout-Check in FUN_10009AC0 entfällt.

📘 Canvas-Anleitung

Alle Details zur Einrichtung, den .def-Dateien, dem VS Code-Setup und den vollständigen C-Quellcodes findest Du in der Canvas-Anleitung im Repository: Proxy & Kernel32 Timeout-fix Anleitung.md.

⚙️ Build & Deploy

Öffne das x86 Native Tools Command Prompt und wechsle in hook-project.

Starte VS Code: code .

Führe Build All Proxies (Ctrl+Shift+B) aus.

Kopiere bin\ws2_32.dll und bin\kernel32.dll in Dein Server-Verzeichnis (neben server.dll).

Starte das Host-Programm. Die neuen Hooks sind aktiv.

ℹ️ Warum zwei DLLs?

Windows lädt beim Aufruf von recv/send und GetTickCount zuerst die DLLs im selben Ordner wie die EXE bzw. die server.dll. Durch das Bereitstellen von ws2_32.dll und kernel32.dll im Server-Ordner werden Deine Proxies automatisch statt der System-DLLs verwendet.

🚨 Bekannte Grenzen

Echte Socket-Errors (non-WSAEWOULDBLOCK), Verbindungsabbrüche und physische Netzwerkprobleme bleiben unberührt.

Sehr hohe Paketverlustraten können zu Blockierungen führen, da Retries endlos wiederholt werden.

Weitere interne Prüfungen in anderen Funktionen der server.dll müssen ggf. ebenfalls gepatcht oder gehookt werden.

📄 Lizenz & Hinweise

Dieses Projekt dient ausschließlich zum Debugging und Testen in eigenen Netzwerken. Achte auf Lizenzbestimmungen und Urheberrechte der Original-server.dll. Jegliche Nutzung erfolgt auf eigene Verantwortung.
