# SecureCord - Service (Windows)

Comme SplitCord-Turkey, SecureCord prévoit un service Windows (SYSTEM) pour maintenir
le tunnel Tor + VPN même si le client est fermé, et pour démarrer au boot.

## Rôle

- Démarrer/arrêter Tor (SOCKS5 127.0.0.1:9050) et le tunnel VPN.
- Exposer une petite API locale (127.0.0.1) pour que le client Electron pilote le service
  sans jamais s'exécuter avec des privilèges élevés.
- Journaliser dans un fichier unique pour le diagnostic.

## Implémentation de référence

Un squelette .NET 8 Worker Service est recommandé (comme SplitCordDpiService).
Fichiers à créer :
- `service/SecureCordService.csproj`
- `service/Program.cs` (Generic Host + Windows Service)
- `service/TorManager.cs`
- `service/VpnManager.cs`
- `service/LocalApi.cs` (HTTP sur 127.0.0.1:58272)

Pour le prototype actuel, le client Electron gère lui-même Tor/VPN (voir `client/src/main.js`),
ce qui suffit pour le développement mais ne persiste pas après fermeture.
