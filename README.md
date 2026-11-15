# SecureCord

Client Discord **sécurisé** inspiré de [SplitCord-Turkey](https://github.com/cagritaskn/SplitCord-Turkey), mais orienté **anonymat et confidentialité** au lieu du contournement DPI.

## Différences clés vs SplitCord-Turkey

| SplitCord-Turkey | SecureCord |
|---|---|
| Contournement DPI (Zapret/ByeDPI/GoodbyeDPI) | Routage anonyme via **Tor + VPN chaînés** |
| Système-entier possible | **Uniquement ce client** (le reste de l'OS reste normal) |
| DNS chiffré anti-censure | DNS chiffré + anti-fuite (WebRTC/QUIC) |
| Vencord optionnel | Vencord optionnel + hardening (CSP, sandbox, anti-fingerprint) |

## Architecture

- `client/` — Application Electron (wrapper Discord web). Applique le proxy SOCKS5 **uniquement à sa session**.
- `service/` — (optionnel) service Windows SYSTEM qui supervise Tor/VPN pour que la connexion persiste même client fermé.
- `scripts/` — récupération des binaires (tor, wg-quick/openvpn).

## Chaînage Tor + VPN

`chainOrder` configurable :
- `vpn-then-tor` (recommandé) : Discord → Tor → (sortie Tor) → VPN → Internet. L'IP visible est celle du VPN, Tor cache l'origine.
- `tor-then-vpn` : Discord → VPN → Tor → Internet. L'IP visible est celle d'un nœud de sortie Tor.

Le proxy exposé à Chromium est le SOCKS5 de Tor (`127.0.0.1:9050`). Le tunnel VPN est monté comme interface réseau que le processus Tor utilise pour ses propres connexions (binding via `OutboundBindAddress` / config Tor).

## Anti-fuite

- WebRTC forcé en `iceTransportPolicy: 'relay'` (pas d'IP locale divulguée) — `preload.js`.
- QUIC désactivé (`--disable-quic`) → pas de fuite UDP hors tunnel.
- DNS chiffré (DoH Cloudflare/Quad9/NextDNS) via `--dns-over-https-templates`.
- Télémétrie et mises à jour en arrière-plan désactivées.
- CSP stricte, sandbox Electron, contextIsolation.

## Lancement (développement)

```bash
cd securecord
npm install
npm start
```

Prérequis : Node.js 22+, Tor installé (ou binaire dans `resources/tor/`), et optionnellement WireGuard/OpenVPN.

## Paramètres

Menu → Fichier → Paramètres. Choisissez le mode de routage, activez Tor/VPN, renseignez le fichier de config VPN, DNS, etc. Redémarrez pour appliquer.

## Anti-fingerprint / anonymat maximal

- User-Agent usurpé + Referer supprimé
- Blocage des trackers/analytics (webRequest)
- Cookies tiers bloqués
- Effacement des données/cache à la fermeture
- Accélération matérielle désactivable (réduction fingerprint)
- DNS distant via Tor (socks5h) — pas de fuite DNS
- Nouvelle identité Tor à la demande (bouton Paramètres)

Ce logiciel est fourni à des fins éducatives et personnelles. L'utilisation de Tor/VPN peut être soumise à des restrictions selon votre juridiction. L'utilisateur est responsable de l'usage qu'il en fait.
