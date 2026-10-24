# Pelagos : document de conception

Oct 24, 2026 · @lio

## 1. Contexte et objectifs

L'outil pilote BIND 9 et Kea au plus près des logiciels, sans dupliquer leur état. Il remplace Webmin et l'ancien tableau de bord Kea, et s'installe aussi bien pour un seul moteur que pour les deux.

**Situation de départ**

- Deux serveurs Debian 13 avec, sur chacun, BIND 9.20 et Kea 2.6.3 (paquets Debian).
- DNS : un primaire (zone `example.lan`, inverses IPv4 `192.0.2.0/24` et IPv6 `2001:db8::/64`, toutes dynamiques) et un secondaire (zones esclaves, NOTIFY). Récursion depuis les racines, validation DNSSEC automatique, une RPZ, statistics-channel JSON et rndc en local seulement.
- DHCP : Kea DHCPv4 en HA hot-standby. Hooks chargés : `lease_cmds`, `ha`. Kea DHCP-DDNS (D2) sur chaque serveur envoie des mises à jour TSIG hmac-sha256 (clé `kea-ddns`) au primaire DNS, seul accepteur (`allow-update { key kea-ddns; }`). Conflits gérés par DHCID (`no-check-with-dhcid`).
- Webmin édite les fichiers de zone à la main alors qu'elles sont dynamiques (journal `.jnl`). Sans `rndc freeze` / `thaw`, c'est une corruption en attente.
- L'ancien tableau de bord Kea : lecture seule, un seul serveur, aucun DNS, scan réseau et SNMP hors sujet.

**Objectifs**

1. Une vue unique DNS + DHCP qui croise les deux : bail sans enregistrement, réservation incohérente, secondaire en retard, pool presque plein.
2. Générique : s'installe sans BIND ni Kea, les installe ensuite à la demande, et pilote BIND seul, Kea seul ou les deux. DHCPv6 est un module optionnel.
3. Reprise d'une configuration existante : l'outil adopte un `named.conf` ou un `kea-dhcp4.conf` déjà en place, sans le réécrire ni perdre une option.
4. Couverture complète : tout ce que BIND et Kea savent faire est configurable, pas seulement ce que l'installation de référence utilise. Exemple : résolution récursive aujourd'hui, mode forward demain.
5. Zéro duplication d'état : la vérité reste dans les fichiers de configuration et les API de BIND et Kea. Aucune base SQL partagée.
6. Portable : paquets deb et rpm, livraison Docker sur les images officielles ISC. L'état propre à l'outil tient dans un fichier de configuration et un journal d'audit.
7. Conscience de la HA : état des deux pairs Kea, serials primaire / secondaire. L'outil est lui-même redondant : un nœud identique sur chaque serveur.
8. Statistiques par élément : chaque instance BIND, chaque serveur Kea DHCPv4 ou DHCPv6, chaque D2.
9. Le système de design d'UCM : thèmes existants gardés, nouveaux thèmes ajoutés.

**Non-objectifs**

- Pas de serveur DNS ou DHCP intégré : l'outil installe et pilote BIND et Kea, il ne les remplace pas.
- Pas de scan réseau, SNMP ni métriques système.
- Pas de multi-moteur au départ (PowerDNS, dnsmasq, ISC DHCP) : BIND 9 et Kea seulement, derrière des connecteurs isolés pour garder la porte ouverte.
- Pas d'édition des fichiers de zone dynamiques : ils ne bougent que par UPDATE. Les configurations de l'utilisateur ne sont jamais réécrites, l'outil n'écrit que dans ses propres fichiers inclus.
- Pas d'IPAM central ni de base partagée : les métadonnées vivent dans les configurations des moteurs.
- Pas de clustering lourd : la réplication entre nœuds se limite au fichier de configuration de l'outil et au journal d'audit.

## 2. État de l'art

Aucun outil libre ne pilote BIND 9 et Kea ensemble, en écriture et en HA : Stork s'en approche mais lit le DNS sans l'écrire, les autres ne couvrent qu'un côté.

| Outil | Ce qu'il fait | Ce qui manque pour ce projet |
| --- | --- | --- |
| [Stork](https://stork.readthedocs.io/en/latest/overview.html) (ISC) | Supervise les démons Kea, affiche l'état HA et les causes de bascule, agrège sous-réseaux et réservations, liste les zones BIND 9 et PowerDNS, verrouille les éditions concurrentes | Pas d'édition d'enregistrements DNS, pas d'IPAM, pas de croisement DNS/DHCP ; les réservations exigent `host_cmds` et vivent dans la base de Stork, pas dans Kea |
| [phpIPAM](https://phpipam.net/) | IPAM IPv4/IPv6, VLAN, VRF, scan de sous-réseaux, API REST, intégration PowerDNS | Ni BIND, ni Kea, ni DHCP |
| [NetBox](https://netboxlabs.com/docs/netbox/en/stable/introduction/) | Source de vérité de l'état voulu du réseau, IPAM, modélisation des équipements | Ne pilote ni DNS ni DHCP ; « DNS server » est explicitement hors périmètre |
| [PowerDNS-Admin](https://github.com/PowerDNS-Admin/PowerDNS-Admin) | Interface web pour zones directes et inverses, gabarits, RBAC, SAML/LDAP, API | PowerDNS Authoritative seulement, pas de DHCP |
| [Technitium DNS Server](https://technitium.com/dns/) | Serveur DNS complet avec console web, DHCP intégré, DNSSEC, clustering (plusieurs instances depuis une console) | Remplace BIND et Kea au lieu de les piloter ; le clustering est une administration centralisée, pas une bascule documentée |
| [Infoblox NIOS](https://www.infoblox.com/products/ddi/) | DDI unifié DNS/DHCP/IPAM sur une console, découverte d'actifs | Propriétaire, appliances, hors d'échelle pour deux serveurs |
| [BlueCat Integrity et Micetro](https://bluecatnetworks.com/products/) | Plateforme « API-first » DNS/DHCP/IPAM, Gateway pour la logique métier | Propriétaire, même constat |
| [EfficientIP SOLIDserver](https://efficientip.com/products/solidserver-ddi/) | DDI unifié, SmartArchitecture pour déployer des paires résilientes, pilotage multi-fournisseur (Microsoft, ISC BIND, Route 53) | Propriétaire ; seule référence qui pilote BIND de l'extérieur, c'est le modèle à retenir |
| [Ancien tableau de bord Kea](https://github.com/NeySlim/ultimate-kea-dhcp-dashboard) | Baux, remplissage des pools, fournisseur OUI via le socket de contrôle ; scan réseau, SNMP, métriques système | Lecture seule, un seul serveur, pas de HA, pas de DNS ; périmètre dilué par le scan et le SNMP |
| Webmin, module BIND | Édite les fichiers de zone et `named.conf` | Ignore les zones dynamiques et leur journal, aucun lien avec Kea |

Leçons à tirer :

- De Stork : surveiller la HA par l'API Kea, verrouiller les éditions ; mais ne jamais garder les réservations hors de Kea.
- De SOLIDserver : piloter les moteurs existants par leurs protocoles au lieu de les remplacer.
- De l'ancien tableau de bord : un périmètre serré, pas de scan ni de SNMP, et l'écriture dès la phase 2.

Sources : pages ci-dessus, ouvertes le 24 octobre 2026.

## 3. Principes et architecture

Chaque serveur fait tourner le même nœud : agent local, API et UI dans un seul paquet. N'importe quel nœud pilote l'ensemble, et les nœuds se répliquent entre eux.

&#91;embedded content: architecture · un nœud identique par serveur, réplication entre nœuds, démons en local\]

Le navigateur parle au nœud de son choix. Chaque nœud atteint ses propres démons en local : rndc et statistics-channel pour BIND, socket de contrôle Unix pour Kea, UPDATE signé pour les zones dynamiques. Les flux existants (NOTIFY et AXFR entre `ns1` et `ns2`, HA Kea, D2 vers le primaire) ne passent pas par l'outil. Plus de SSH, plus de base centrale.

**Principes**

1. Les moteurs sont la vérité : BIND pour les zones, Kea pour les baux, les réservations et les sous-réseaux. L'outil relit avant d'afficher.
2. La configuration vit dans les fichiers des moteurs. Kea garde les métadonnées dans `user-context` ; pour BIND, l'outil écrit dans ses propres fichiers `include`, jamais dans le `named.conf` de l'utilisateur.
3. Une écriture = le canal natif du logiciel : UPDATE signé pour une zone dynamique, commande sur le socket de contrôle pour Kea, fichier inclus puis `rndc reconfig` pour la configuration BIND.
4. Toute écriture de fichier suit la même séquence : sauvegarde, validation (`named-checkconf`, `kea-dhcp4 -t`), rechargement, retour arrière si le démon refuse.
5. Deux niveaux d'édition, pour couvrir tout sans un formulaire par option : des écrans dédiés pour les fonctions courantes, et un éditeur avancé piloté par la grammaire du logiciel (statements de `named.conf`, JSON complet de Kea) pour le reste. Même validation, même diff, même retour arrière. Une option inconnue de l'outil est conservée telle quelle à l'import.
6. Chaque écriture est prévisualisée (diff), conditionnelle (prérequis, hash de configuration), journalisée et réversible.
7. Le nœud est local à son serveur : sockets Unix, rndc local, aucun accès distant aux démons. Les nœuds ne se parlent qu'entre eux, en HTTPS mTLS.
8. L'état propre à l'outil est minuscule et répliqué : un fichier de configuration (pairs, utilisateurs, réglages) et un journal d'audit JSONL. Les séries des graphes sont un cache SQLite local, reconstruisible, non répliqué.
9. Les connecteurs sont les seuls à connaître les protocoles ; le reste manipule des zones, des enregistrements, des baux, des réservations.
10. Lecture seule d'abord : aucune écriture avant que l'observation soit fiable (phase 1).

## 4. Intégration BIND

BIND est piloté par ses canaux natifs, tous locaux au nœud : UPDATE signé TSIG pour les données, rndc pour le contrôle, statistics-channel JSON pour l'observation, fichiers inclus pour la configuration. L'outil ne réécrit jamais un fichier de zone ni le `named.conf` de l'utilisateur.

| Besoin | Canal | Remarque |
| --- | --- | --- |
| Lire une zone | AXFR avec une clé TSIG de lecture (`allow-transfer { key ddi-read; }`) | Lu sur `ns1` et `ns2` : même contenu, même serial, sinon alerte |
| Écrire un enregistrement | UPDATE RFC 2136 signé TSIG, clé dédiée `ddi-admin`, envoyé par dnspython | Prérequis `yxrrset` / `nxrrset` : l'écriture échoue si la zone a bougé entre l'aperçu et l'envoi ([nsupdate](https://bind9.readthedocs.io/en/v9.20.0/manpages.html)) |
| État d'une zone, serial, dynamique ou non, signature | `rndc zonestatus` | Local au nœud, avec la clé rndc du serveur |
| Forcer un secondaire en retard | `rndc retransfer` sur le secondaire, `rndc notify` sur le primaire | Chaque nœud joue sa commande en local ; phase 1, bouton « resynchroniser » |
| Compteurs par instance BIND | statistics-channel JSON, lu en local par chaque nœud ([ARM, BIND 9 Statistics](https://bind9.readthedocs.io/en/v9.20.0/reference.html)) | Une série par instance, `ns1` et `ns2` séparés |
| Reprendre une configuration existante | `named-checkconf -p` donne la configuration résolue : zones, clés, ACL, options, `include` | Phase 0 : import sans réécriture ; l'outil ajoute seulement une ligne `include` vers son dossier |
| Clés, ACL, options gérées par l'outil | Fichiers inclus écrits par l'outil, `named-checkconf` puis `rndc reconfig` | Sauvegarde, validation, rechargement, retour arrière |
| Ajouter ou retirer une zone | Déclaration dans un fichier inclus puis `rndc reconfig` ; catalog zone pour les secondaires ([ARM, Catalog Zones](https://bind9.readthedocs.io/en/v9.20.0/chapter6.html)) | Phase 4 |
| DNSSEC | `rndc dnssec -status`, `dnssec-policy` | Lecture seule avant la phase 4 |
| RPZ | Zone dynamique ordinaire : mêmes UPDATE | Phase 4 |

**Règles**

- Une zone dynamique ne se modifie que par UPDATE. `rndc freeze` / `thaw` est réservé à un mode maintenance explicite, jamais utilisé par l'éditeur.
- L'outil a ses propres clés TSIG, distinctes de `kea-ddns`. Le primaire passe de `allow-update { key kea-ddns; }` à un `update-policy` qui nomme les deux clés.
- `update-policy` décidé : `grant ddi-admin zonesub A AAAA PTR CNAME TXT SRV MX DHCID;` et `grant kea-ddns zonesub A AAAA PTR DHCID;`. DHCID est inclus pour `ddi-admin` : sans lui, l'outil ne peut pas nettoyer un nom laissé par un bail. Jamais SOA ni les types DNSSEC : ils restent à BIND.
- Aperçu du diff : l'outil lit le RRset courant, construit l'UPDATE avec ses prérequis, affiche avant / après, envoie, journalise la requête et le code de réponse.
- La synchro primaire / secondaire se mesure par le serial SOA interrogé sur chaque serveur, pas par le fichier.
- Les erreurs DDNS se lisent côté Kea D2 (section 5) et, en option, dans la catégorie `update` du journal de `named`.
- Mise à niveau de sécurité : l'assistant d'audit (section 9) détecte les clés `hmac-md5` (TSIG, rndc), propose `hmac-sha256`, et bascule les deux côtés ensemble pour une clé partagée avec Kea.

**Couverture des fonctions BIND**

Tout `named.conf` doit rester configurable, pas seulement la récursion directe de l'installation de référence. Les fonctions courantes ont un écran ; le reste passe par l'éditeur avancé, qui connaît la grammaire des statements ([ARM 9.20, référence](https://bind9.readthedocs.io/en/v9.20.0/reference.html)) et n'applique rien sans `named-checkconf`.

| Fonction | Statements BIND | Écran dédié ou éditeur avancé | Phase |
| --- | --- | --- | --- |
| Résolution récursive | `recursion`, `allow-recursion` | Écran dédié | 2 |
| Forward global ou par zone | `forwarders`, `forward first` / `forward only`, `type forward` | Écran dédié | 2 |
| Zones primaires et secondaires | `type primary`, `type secondary`, `primaries`, `also-notify`, `notify` | Écran dédié | 2 |
| Autres types de zones | `type stub`, `static-stub`, `mirror`, `hint`, `redirect` | Stub par écran dédié ; le reste par l'éditeur avancé | 2 / 4 |
| Catalog zones | `catalog-zones` | Écran dédié | 4 |
| Vues | `view` | Éditeur avancé | 4 |
| ACL et droits | `acl`, `allow-query`, `allow-transfer`, `allow-update`, `update-policy` | Écran dédié | 2 |
| Clés TSIG | `key` (`hmac-sha256` et plus ; `hmac-md5` signalé par l'audit) | Écran dédié | 0 / 2 |
| RPZ | `response-policy` | Écran dédié | 4 |
| DNSSEC | `dnssec-validation`, `dnssec-policy` | Lecture en phase 1, écran dédié en phase 4 | 1 / 4 |
| Limitation de débit (RRL) | `rate-limit` | Éditeur avancé | 4 |
| Journalisation | `logging`, `channel`, `category` | Éditeur avancé | 4 |
| Statistiques | `statistics-channels` | Activé à l'installation, lu dès la phase 1 | 0 / 1 |
| Tout le reste | N'importe quel statement de la grammaire | Éditeur avancé | 4 |

**Accès local**

rndc et le statistics-channel écoutent en local, et cela suffit : le nœud tourne sur le serveur. Il lit la clé rndc du serveur (ou une clé dédiée déclarée dans un fichier inclus) et interroge le statistics-channel sur son adresse locale. Ni SSH ni agent distant : un nœud ne parle à un autre nœud que pour répliquer son état (section 9).

## 5. Intégration Kea et HA

Kea se pilote par le socket de contrôle de chaque démon, en local sur le nœud. Kea 3.x est la cible : `host_cmds` et `subnet_cmds` y sont libres. Kea 2.6 reste pris en charge en mode dégradé, sans ces deux hooks.

**Ce que Kea 2.6 permet déjà (mode dégradé)**

| Besoin | Commande ou hook | Disponible en 2.6.3 |
| --- | --- | --- |
| État HA (state, role, scopes, in-touch des deux pairs) | `status-get` avec le hook `ha` ([ARM 2.6.3](https://kea.readthedocs.io/en/kea-2.6.3/arm/hooks.html)) | Oui, chargé |
| Baux, recherche, page par page | `lease4-get-all`, `lease4-get-page`, `lease4-get-by-hw-address` (hook `lease_cmds`) | Oui, chargé |
| Remplissage des sous-réseaux | `statistic-get-all` : `subnet[id].total-addresses`, `assigned-addresses` | Oui |
| Statistiques par sous-réseau à la demande | hook `stat_cmds` | Installé, non chargé |
| Configuration complète | `config-get`, `config-test`, `config-set`, `config-write`, `config-hash-get` | Oui |
| Réservations par API, sans recharger | hook `host_cmds` (`reservation-add`, `reservation-del`) | Non : « ISC premium library » en 2.6.3 |
| Sous-réseaux par API | hook `subnet_cmds` | Non : clients support ISC en 2.6.3 |
| Erreurs DDNS | D2 : `statistic-get-all`, compteurs `update-sent`, `update-error`, `update-timeout`, aussi par clé `key[kea-ddns.].update-error` ([ARM D2](https://kea.readthedocs.io/en/kea-2.6.3/arm/ddns.html)) | Oui |

Depuis Kea 3.0, ISC a libéré `host_cmds`, `subnet_cmds`, `stat_cmds`, `lease_cmds` et `ha` ; seuls `rbac` et `cb_cmds` restent réservés aux clients support ([annonce Kea 3.0](https://www.isc.org/blogs/kea-3-0/), [ARM, hooks](https://kea.readthedocs.io/en/latest/arm/hooks.html)). Depuis Kea 2.7.2, chaque démon ouvre lui-même des sockets HTTP ou HTTPS et le Control Agent n'est plus nécessaire ; il est supprimé depuis Kea 3.1.8, et depuis 3.3.1 seule la clé `control-sockets` est reconnue ([ARM, canal de contrôle](https://kea.readthedocs.io/en/latest/arm/ctrl-channel.html)). ISC fournit des paquets deb (Debian, Ubuntu) et rpm (RHEL, Fedora) via Cloudsmith, hooks dans `isc-kea-hooks` ([paquets ISC](https://kb.isc.org/docs/isc-kea-packages.md), [installation](https://kea.readthedocs.io/en/latest/arm/install.html)).

**Réservations et sous-réseaux : deux voies**

1. Kea 3.x, la cible : `reservation-add`, `reservation-del`, `subnet4-add`, `subnet4-update` sur le socket de chaque pair, puis `config-write` pour que le fichier reste la vérité. Une commande par objet, jouée sur les deux pairs.
2. Kea 2.6, le secours : aller-retour `config-get`, édition du tableau `reservations` ou `subnet4`, `config-test`, `config-set`, `config-write`, sur chaque pair. Recharge toute la configuration ; reste utile en 3.x pour les options et les paramètres globaux.

Dans les deux voies, les métadonnées de l'outil (notes, étiquettes, propriétaire) vont dans le `user-context` de l'objet Kea : elles voyagent avec la configuration, sans base à côté.

**Canal de contrôle**

- Chaque démon (`kea-dhcp4`, `kea-dhcp6`, `kea-dhcp-ddns`) expose son socket de contrôle Unix ; le nœud local s'y connecte directement, même commande JSON en 2.6 et en 3.x.
- Statistiques par élément : `statistic-get-all` sur le socket de chaque démon, donc une série par serveur DHCPv4, par serveur DHCPv6 et par D2.
- Entre serveurs, l'outil ne parle jamais à un Kea distant : il parle au nœud de l'autre serveur, qui parle à son Kea. Les sockets HTTPS natifs (Kea 2.7.2 et plus) restent possibles pour un serveur sans nœud, en option.
- `kea-ctrl-agent` n'est plus requis ; il reste reconnu en compatibilité pour un Kea 2.6 que l'on ne peut atteindre que par HTTP.
- Pair HA : l'écoute dédiée du hook `ha` (`http-dedicated-listener`) ne sert qu'aux échanges HA. Elle n'est pas une API d'administration.

**Règles HA**

- Toute lecture se fait sur les deux pairs ; un écart de baux ou d'état entre eux est une alerte, pas un détail.
- Toute écriture de configuration est transactionnelle : même contenu sur les deux pairs, `config-hash-get` avant et après, retour arrière si un pair refuse.
- Les baux ne s'écrivent jamais à la main sauf suppression explicite (`lease4-del`) ; la HA les réplique.
- Le mode maintenance HA (`ha-maintenance-start`, `ha-maintenance-cancel`) est exposé avec confirmation, pour les mises à jour de paquets.
- DHCPv6 est un module optionnel : même modèle avec `kea-dhcp6`, son socket, ses commandes `lease6-*` et `subnet6-*`, sa propre HA. Rien n'est affiché tant qu'il n'est pas activé.

**Couverture des fonctions Kea**

La configuration JSON de Kea est couverte en entier : écrans dédiés pour le courant, éditeur avancé sur le JSON complet pour le reste, `kea-dhcp4 -t` ou `kea-dhcp6 -t` avant toute application ([ARM, kea-dhcp4](https://kea.readthedocs.io/en/latest/arm/dhcp4-srv.html), [ARM, kea-dhcp6](https://kea.readthedocs.io/en/latest/arm/dhcp6-srv.html), [ARM, hooks](https://kea.readthedocs.io/en/latest/arm/hooks.html)).

| Fonction | Clés Kea | Écran dédié ou éditeur avancé | Phase |
| --- | --- | --- | --- |
| Sous-réseaux et pools | `subnet4`, `subnet6`, `pools` | Écran dédié | 3 |
| Réseaux partagés | `shared-networks` | Écran dédié | 3 |
| Options et définitions d'options | `option-data`, `option-def` | Options courantes par écran dédié ; `option-def` par l'éditeur avancé | 3 / 4 |
| Classes de clients | `client-classes` | Écran dédié | 3 |
| Réservations | `reservations` (`hw-address`, `duid`, `client-id`, `circuit-id`) | Écran dédié | 3 |
| Haute disponibilité | hook `ha`, `mode` : `hot-standby`, `load-balancing`, `passive-backup` | État et maintenance en phase 1, configuration en phase 3 | 1 / 3 |
| Backend de baux | `lease-database` : `memfile`, `mysql`, `postgresql` | Lecture en phase 1 ; éditeur avancé | 1 / 4 |
| Hooks | `hooks-libraries` | Activation des hooks ISC par écran dédié ; paramètres par l'éditeur avancé | 3 / 4 |
| DDNS | `dhcp-ddns`, `ddns-send-updates`, `ddns-qualifying-suffix`, `ddns-conflict-resolution-mode` | Écran dédié | 3 |
| DHCPv6 et délégation de préfixe | `subnet6`, `pd-pools` (`prefix`, `prefix-len`, `delegated-len`) | Module optionnel, mêmes écrans | 3 |
| Sockets de contrôle | `control-sockets` | Posés à l'installation ou à l'import | 0 |
| Tout le reste | N'importe quelle clé du JSON | Éditeur avancé | 4 |

## 6. Modèle de données

Toute donnée vit dans les fichiers ou les démons de BIND et Kea ; l'outil n'a à lui qu'un fichier de configuration, un journal d'audit et un cache local de séries. Pas d'IPAM central, pas de base SQL partagée.

| Donnée | Où elle vit | Répliquée ? |
| --- | --- | --- |
| Enregistrements DNS (A, AAAA, PTR, CNAME, TXT, SRV, MX, DHCID) | BIND : zone dynamique et son journal | Par BIND, vers le secondaire (NOTIFY, AXFR / IXFR) |
| Zones, clés, ACL, options BIND | `named.conf` de l'utilisateur (jamais réécrit) et fichiers inclus de l'outil | Par l'outil : chaque nœud écrit les includes de son serveur ; les zones atteignent les secondaires par catalog zone |
| Serial SOA et état de chaque zone | BIND (`rndc zonestatus`, requête SOA), lu en direct | Non ; l'historique des écarts est un cache local |
| Baux DHCP | Kea (memfile ou base), répliqués par la HA | Par Kea |
| Sous-réseaux, pools, options, classes, réservations | Fichier de configuration Kea de chaque pair, fixé par `config-write` | Par l'outil : même écriture sur les deux pairs, `config-hash-get` avant et après |
| Notes, étiquettes, propriétaire d'un objet DHCP | `user-context` de l'objet Kea (sous-réseau, pool, réservation) | Avec la configuration Kea |
| Notes sur une zone ou une clé BIND | Commentaire structuré dans le fichier inclus de l'outil | Avec le fichier inclus |
| État HA Kea, compteurs BIND, Kea et D2 | Démons (`status-get`, statistics-channel, `statistic-get-all`), lus en direct | Non ; les séries sont un cache SQLite local par nœud, reconstruisible |
| Configuration de l'outil : pairs, utilisateurs, rôles, réglages, modules actifs | Un fichier sur chaque nœud | Oui : version monotone, dernier écrivain gagne |
| Journal d'audit : qui, quoi, quand, requête, réponse, diff | Fichier JSONL en ajout seul sur chaque nœud | Oui : fusion idempotente par id d'entrée |
| Secrets de l'outil : clés TSIG `ddi-*`, certificats mTLS, secrets TOTP | Fichier de configuration de l'outil, chiffrés par une clé maître locale | Oui, chiffrés ; la clé maître est remise à l'enrôlement du nœud, jamais répliquée |
| Incohérences DNS / DHCP | Calculées à chaque passage | Non ; un acquittement est une entrée d'audit, donc répliqué |
| Sessions web | Mémoire du nœud | Non : changer de nœud demande une reconnexion |

**Réplication entre nœuds**

Les nœuds se parlent en HTTPS mTLS, et seulement pour deux fichiers. La configuration de l'outil porte un numéro de version monotone : la version la plus haute gagne, et à version égale le dernier écrivain. Le journal d'audit se fusionne par id d'entrée, sans conflit possible. Un nœud qui revient tire ce qui lui manque chez ses pairs avant de servir l'interface ; il n'y a ni élection ni quorum.

**La vue « hôte » est une jointure, pas une table**

Un hôte affiché réunit, par adresse MAC puis par IP puis par nom : le bail Kea, la réservation Kea et son `user-context`, les enregistrements A, AAAA et PTR de BIND. L'outil ne persiste rien : tout est relu à chaque affichage ou servi depuis le cache.

**Rétention**

Les séries sont un cache SQLite local à chaque nœud, reconstruisible, purgé selon la table ci-dessous. Toutes les valeurs sont configurables.

| Série | Précision | Durée gardée |
| --- | --- | --- |
| Remplissage des pools | 1 relevé / 5 min, puis 1 / heure après 7 jours | 1 an |
| Serials (écart primaire / secondaire) | À chaque changement | 90 jours |
| Bascules HA | Chaque événement | 1 an |
| Journal d'audit | Sans objet | Jamais purgé par l'outil |

## 7. Fonctionnalités par phase

Cinq phases, de l'installation à la couverture complète ; chaque phase s'ouvre sur un critère vérifiable, pas sur une date. Les fonctions courantes s'écrivent dès les phases 2 et 3, le reste par l'éditeur avancé en phase 4.

&#91;embedded content: feuille de route · 5 phases, 4 portes\]

La porte d'une phase est un état des serveurs, pas un jalon de calendrier : tant que le critère n'est pas rempli, la phase précédente continue.

**Détail des portes**

1. Avant la phase 1 : le nœud tourne sur chaque serveur, lit ses sockets locaux (rndc, statistics-channel, sockets Kea), les pairs sont enrôlés en mTLS, et l'import rend une configuration identique à celle lue.
2. Avant la phase 2 : clés `ddi-read` et `ddi-admin` créées, `update-policy` déployé sur le primaire, retour arrière testé sur une zone de test.
3. Avant la phase 3 : Kea 3.x avec `host_cmds` et `subnet_cmds` sur les deux pairs, ou décision explicite de rester en mode dégradé 2.6 (`config-set`).
4. Avant la phase 4 : l'import sans perte est vérifié sur les configurations réelles, et aucune incohérence DNS/DHCP n'est ouverte depuis la mise en service de la phase 3.

**Ce que chaque phase livre**

- Phase 0 : paquets deb et rpm, livraison Docker ; installation de BIND et / ou Kea à la demande ; import d'une configuration existante sans réécriture ; assistant d'audit de sécurité (md5 vers sha256) ; sockets de contrôle, statistics-channel et fichiers inclus posés ; enrôlement des nœuds.
- Phase 1 : tableaux de bord répliqués, baux avec recherche, remplissage par sous-réseau et par pool, écart de serial `ns1` / `ns2`, compteurs D2 par clé, statistiques par instance BIND, DHCPv4, DHCPv6 et D2, bouton « resynchroniser le secondaire ».
- Phase 2 : lecture des zones par AXFR, éditeur A, AAAA, PTR, CNAME, TXT, SRV, MX avec aperçu du diff, audit et UPDATE inverse ; zones primaires, secondaires, forward et stub ; forwarders, récursion, ACL, clés TSIG, transferts et NOTIFY par fichiers inclus.
- Phase 3 : sous-réseaux, pools, réseaux partagés, options, classes et réservations sur les deux pairs ; notes en `user-context` ; création groupée A + PTR, fiche hôte ; HA (mode, maintenance) ; DDNS ; module DHCPv6 avec délégation de préfixe.
- Phase 4 : éditeur avancé piloté par la grammaire (tout `named.conf`, tout le JSON Kea) ; catalog zones, RPZ, vues, RRL, journalisation ; DNSSEC (`dnssec-policy`, états, NTA) ; hooks, backends de baux, `option-def` ; export git en lecture seule de `named.conf`, des zones et de la configuration Kea.

## 8. Interface et système de design

Le frontend reprend celui d'UCM par copie, composants et tokens inchangés. Les trois familles de thèmes existantes restent, et de nouvelles s'ajoutent dans les deux mêmes fichiers, dont « Pelagic : Ocean Mission Control UI ».

**Ce qu'est le système de design UCM** (dépôt [ultimate-ca-manager](https://github.com/NeySlim/ultimate-ca-manager), dossier `frontend/`)

- Stack : React 18, Vite 7, Tailwind 3, primitives Radix (dialog, dropdown, select, switch, tabs, toast, tooltip), react-router 7, i18next, recharts, react-grid-layout, socket.io-client, sonner. Tests Vitest et Playwright.
- Tokens : `frontend/src/contexts/ThemeContext.jsx` définit trois familles (`gray`, `purple`, `sunset`), chacune en `dark` et `light`, et écrit les variables CSS `--bg-*`, `--text-*`, `--accent-*`, `--border`, `--gradient-*`, `--icon-*-{bg,text}` sur `documentElement`. Mode `system` / `dark` / `light`, persisté en localStorage et côté serveur.
- `frontend/src/index.css` (2 900 lignes) : polices auto-hébergées, valeurs par défaut `:root` et `.theme-light`, ombres en couches, verre dépoli, classes `card-soft`, `btn-gradient`, `badge-enhanced`, `status-*-bg`, `elevation-*`.
- `frontend/tailwind.config.js` : alias Tailwind vers les variables (`bg-bg-primary`, `text-text-secondary`, `status-success`), tailles `2xs` / `3xs`, rayons 2 à 8 px.
- `frontend/src/DESIGN_SYSTEM.md` : la référence écrite, à copier telle quelle.
- Composants : `AppShell`, `Sidebar` (groupes de navigation), `CommandPalette`, `UnifiedPageHeader`, `RichStatsBar`, `FilterChips`, `Card`, `Badge`, `Button`, `FormModal`, `FloatingDetailWindow`, `Pagination`, `EmptyState`, `StatusIndicator`, `DashboardChart`.
- Icônes Phosphor (`@phosphor-icons/react`) ; typo Inter pour l'UI, Fira Code pour les valeurs techniques (`public/fonts/`).

**Méthode de réutilisation : copie, pas paquet partagé**

Les composants UCM importent ses services, ses permissions et son i18n (`AppShell.jsx` charge `certificatesService` et les `navGroups` PKI). Les extraire en paquet demande d'abord de les découpler. Pour la phase 1 : copier `index.css`, `tailwind.config.js`, `ThemeContext.jsx`, `DESIGN_SYSTEM.md`, les polices et les composants génériques (`components/*.jsx` hors PKI, `components/ui/`). Un paquet partagé se justifiera quand les deux projets voudront le même correctif. Licence : le code repris d'UCM est relicencié en Apache-2.0 par son auteur (section 10).

**Ce qui change : des familles en plus dans `ThemeContext.jsx` et les blocs `:root` / `.theme-light` d'`index.css`**

Les familles `gray`, `purple` (Purple Night) et `sunset` (Orange Sunset) restent telles quelles, chacune en clair et en sombre. Nouvelle famille par défaut : « Pelagic : Ocean Mission Control UI », fond abyssal, turquoise pour le DNS et les actions, bleu ciel pour le DHCP. Les couleurs d'état ne bougent pas : elles portent un sens, pas une marque.

| Token | UCM `gray` sombre | UCM `gray` clair | Pelagic sombre | Pelagic clair |
| --- | --- | --- | --- | --- |
| `--bg-primary` | `#12161C` | `#EFF2F7` | `#061420` | `#EEF5F7` |
| `--bg-secondary` | `#1C222A` | `#FFFFFF` | `#0B1E2E` | `#FFFFFF` |
| `--bg-tertiary` | `#252D38` | `#E4E8EF` | `#12293C` | `#DCE9EE` |
| `--text-primary` | `#F0F4F8` | `#111827` | `#E6F3F5` | `#0B1E2E` |
| `--text-secondary` | `#A8B4C4` | `#4B5563` | `#9FBFCB` | `#3C5B68` |
| `--text-tertiary` | `#7E8A9A` | `#6B7280` | `#6E8F9C` | `#4A6977` |
| `--accent-primary` | `#4F8EF7` | `#2563EB` | `#2DD4BF` | `#0F766E` |
| `--accent-pro` | `#A78BFA` | `#7C3AED` | `#93C5FD` | `#1D4ED8` |
| `--accent-success` | `#34D399` | `#059669` | inchangé | inchangé |
| `--accent-warning` | `#FBBF24` | `#D97706` | inchangé | inchangé |
| `--accent-danger` | `#F87171` | `#DC2626` | inchangé | inchangé |
| `--border` | `#3A4555` | `#CBD5E1` | `#1E3A4C` | `#BFD3DB` |
| `--gradient-from` / `--gradient-to` | `#4F8EF7` / `#A78BFA` | `#2563EB` / `#7C3AED` | `#2DD4BF` / `#93C5FD` | `#0F766E` / `#1D4ED8` |
| `--logo-gradient-*` | orange `#fb923c` à `#ea580c` | idem | turquoise `#2DD4BF` à `#0F766E` | idem |

Règle d'usage : `accent-primary` = DNS et actions principales, `accent-pro` = DHCP, les badges `status-*` = santé. Les tokens `--icon-*` suivent la même logique (`icon-blue` devient turquoise, `icon-violet` reste pour le DHCP). Contrastes calculés sur `--bg-secondary` (WCAG 2) : texte primaire 14,9:1 sombre et 16,9:1 clair, texte secondaire 8,7:1 et 7,3:1, texte tertiaire 4,9:1 et 5,9:1, accents 9,1:1 et 5,5:1 ; tous au-dessus de 4,5:1 (AA). À confirmer sur les composants réels avant de figer.

Autres familles proposées, une ligne chacune :

- « Boreal » : fond graphite froid, vert aurore pour le DNS, violet pour le DHCP, pour qui trouve Pelagic trop bleu.
- « Paper » : clair seulement, blanc cassé et encre, un seul accent bleu, pour l'impression et les écrans très lumineux.

**Navigation proposée** (même `Sidebar` groupée qu'UCM)

1. Tableau de bord : tuiles HA, pools, synchro des zones, erreurs DDNS, incohérences, état des nœuds.
2. DNS : zones, enregistrements, résolution et forward, ACL et clés, secondaires, DNSSEC, RPZ.
3. DHCP : sous-réseaux et pools, réseaux partagés, options, classes, baux, réservations, HA ; DHCPv6 si le module est actif.
4. Hôtes : vue croisée bail / réservation / enregistrements, incohérences.
5. Configuration avancée : éditeur piloté par la grammaire pour `named.conf` et le JSON Kea, diff, validation, historique.
6. Administration : nœuds et réplication, modules (BIND, Kea, DHCPv6), installation et import, audit de sécurité, utilisateurs et rôles, journal d'audit, paramètres.

**Écrans clés**

- Fiche hôte dans une `FloatingDetailWindow` : bail, réservation et son `user-context`, A / AAAA / PTR, actions croisées.
- Éditeur d'enregistrement en `FormModal` avec aperçu du diff avant / après et code de réponse après envoi.
- Éditeur avancé : arbre des statements ou du JSON à gauche, formulaire généré depuis la grammaire à droite, diff et résultat de `named-checkconf` / `kea-dhcp4 -t` avant le bouton « appliquer ».
- Assistant d'import et d'audit : ce qui a été lu, ce qui sera ajouté (une ligne `include`, des sockets), ce qui est à durcir (clés md5), un plan à valider étape par étape.
- Liste des incohérences avec `FilterChips` par type et par serveur, acquittement par ligne.
- Tableau de bord sur `react-grid-layout`, tuiles déplaçables comme dans UCM, identiques sur chaque nœud.

## 9. Sécurité

L'outil détient des secrets qui écrivent dans le DNS et le DHCP : chaque canal a sa clé dédiée, le moins de droits possible, rien ne sort du serveur sauf la réplication entre nœuds en mTLS. Il remet aussi à niveau les configurations qu'il reprend.

**Vers BIND**

- Deux clés TSIG hmac-sha256 propres à l'outil : `ddi-read` (AXFR) et `ddi-admin` (UPDATE). Jamais la clé `kea-ddns`.
- `update-policy` par zone, tel que décidé en section 4 : `ddi-admin` sur A, AAAA, PTR, CNAME, TXT, SRV, MX, DHCID ; `kea-ddns` sur A, AAAA, PTR, DHCID ; ni SOA ni types DNSSEC pour personne.
- Les UPDATE partent de la bibliothèque dnspython, pas d'un `nsupdate` en sous-processus : pas d'interpolation de shell, pas de secret sur la ligne de commande.
- rndc et le statistics-channel restent locaux au serveur ; le nœud les joint en local, avec la clé rndc du serveur en hmac-sha256. Aucun SSH, aucun port ouvert pour eux.
- Les fichiers inclus de l'outil sont écrits avec les droits du groupe de `named`, lecture seule pour les autres ; les secrets TSIG y sont déclarés dans un fichier séparé en `0640`.
- DNSSEC : l'outil ne touche jamais une clé privée ; `dnssec-policy` de BIND fait la rotation, l'outil lit `rndc dnssec -status`.

**Assistant d'audit de configuration**

Une configuration reprise est d'abord auditée, puis durcie étape par étape, jamais d'un bloc. L'assistant détecte, propose un plan, applique avec sauvegarde, vérifie (`named-checkconf`, `kea-dhcp4 -t`, rechargement, test fonctionnel) et revient en arrière si une étape échoue.

- Clés TSIG et rndc en `hmac-md5` ou `hmac-sha1` : remplacement par `hmac-sha256` au minimum, nouveau secret généré.
- Clé partagée avec Kea (`kea-ddns`) : BIND accepte temporairement l'ancienne et la nouvelle clé dans `update-policy`, D2 bascule sur la nouvelle sur les deux pairs, puis l'ancienne est retirée. Jamais un seul côté à la fois.
- Autres durcissements détectés : `allow-update` par adresse IP remplacé par une clé, `allow-transfer` ouvert, récursion ouverte à tous, `rndc` ou statistics-channel à l'écoute hors de l'hôte local, `kea-ctrl-agent` en HTTP clair, sockets Kea sans droits restreints, `dnssec-validation` désactivée.
- Chaque point est une ligne du plan : constat, changement proposé, risque, case à cocher. L'utilisateur choisit ; rien n'est appliqué sans son accord.

**Vers Kea**

- Le nœud parle à chaque démon Kea par son socket de contrôle Unix, droits restreints à l'utilisateur du nœud et au groupe de Kea. Aucun port d'administration Kea ouvert sur le réseau.
- Un socket HTTPS natif de Kea (2.7.2 et plus) n'est configuré que pour un serveur sans nœud, avec `trust-anchor`, `cert-file` et `cert-required` ; `kea-ctrl-agent` en HTTP clair est signalé par l'audit.
- `config-set` n'est jamais envoyé sans `config-test` réussi ; `config-write` n'est envoyé qu'après succès sur les deux pairs.
- Le mode maintenance HA et `dhcp-disable` exigent une confirmation explicite et un rôle dédié.

**Dans l'outil**

- Authentification et RBAC repris d'UCM (`backend/auth`, `backend/security`) : mots de passe argon2, TOTP, WebAuthn, sessions, limitation de débit. Les utilisateurs et rôles sont dans la configuration répliquée : le même compte ouvre chaque nœud.
- Rôles minimaux : lecture, opérateur DNS, opérateur DHCP, administrateur. Un opérateur DNS ne voit pas les secrets Kea.
- Entre nœuds : HTTPS mTLS, certificats émis à l'enrôlement par le premier nœud (CA interne de l'outil) ou par UCM si une CA existe déjà. Un nœud inconnu est refusé ; l'enrôlement passe par un jeton à usage unique.
- Secrets chiffrés au repos dans la configuration de l'outil, clé maître hors du fichier, remise une fois à l'enrôlement, comme UCM.
- Audit en ajout seul, fichier JSONL répliqué : utilisateur, nœud, horodatage, requête envoyée (UPDATE, commande Kea, fichier écrit), réponse reçue, diff avant / après. Toute écriture a son retour arrière préparé.
- Chaque nœud n'écoute que sur le réseau d'administration, en HTTPS, derrière le même gunicorn TLS qu'UCM.
- Les données lues chez BIND et Kea (noms d'hôtes DHCP, TXT, `user-context`) sont traitées comme non fiables : échappées à l'affichage, jamais interprétées.

## 10. Choix techniques et déploiement

La stack UCM est retenue : Python et Flask au backend, React et Vite au frontend. Un seul paquet par cible (deb, rpm, image Docker) livre le nœud complet, serveur web et collecteur, sous licence Apache-2.0.

**Pourquoi la stack UCM**

| Brique | UCM (`backend/requirements.txt`, `frontend/package.json`) | Ce que le DDI en fait |
| --- | --- | --- |
| Python 3.13, Flask 3, Flask-RESTX | API REST documentée | Reprise telle quelle avec `backend/auth`, `security`, `middleware` ; Flask-SQLAlchemy ne sert plus qu'au cache de séries |
| dnspython 2.8 | Déjà présent pour ACME | UPDATE signés TSIG, AXFR, requêtes SOA : tout le connecteur BIND sans sous-processus |
| Grammaire de `named.conf` | Absente d'UCM | Parseur et sérialiseur maison, nourris par la grammaire publiée dans les sources de BIND et contrôlés par `named-checkconf -p` ; base de l'import et de l'éditeur avancé |
| gunicorn + gevent, worker WebSocket | Un worker, 1 000 connexions | Pousser l'état HA et les alertes en direct |
| SQLite | Base d'UCM | Cache local de séries seulement, reconstruisible ; la configuration et l'audit de l'outil sont des fichiers |
| React 18, Vite, Tailwind, Radix, recharts, i18next | Le système de design de la section 8 | Copié tel quel, thèmes en plus |
| `.deb`, `.rpm`, Docker, `packaging/systemd` | Un installeur par cible | Même outillage ; code dans `/opt/<outil>`, configuration dans `/etc/<outil>`, état dans `/var/lib/<outil>` |

**Nuances**

- Un collecteur séparé : UCM tourne en un seul worker gevent. Le nœud interroge en boucle ses démons locaux et les nœuds pairs ; ces boucles vivent dans un second processus (`<outil>-collector`) qui écrit le cache de séries et les alertes, le serveur web lit. Deux unités systemd, un paquet.
- Flask plutôt que FastAPI : l'asynchrone n'apporte rien pour une dizaine de requêtes par cycle, et la réutilisation de l'authentification, du RBAC et de l'audit d'UCM pèse plus lourd que le typage. À revoir si le nombre de serveurs pilotés dépasse la dizaine.
- Réplication : un petit module sans dépendance nouvelle, client et serveur HTTPS mTLS dans le collecteur, version monotone pour la configuration, fusion par id pour l'audit.
- Connecteurs comme interfaces : `DnsBackend` (BIND) et `DhcpBackend` (Kea) sont les seuls modules qui connaissent les protocoles. Tout le reste manipule des zones, des enregistrements, des baux et des réservations abstraits.
- Cache : mémoire du processus web avec expiration par TTL, pas de Redis.

**Trois modes d'installation**

1. Serveur nu : le paquet du nœud installe, à la demande et au choix, `bind9` et / ou `isc-kea` depuis la distribution ou depuis les dépôts ISC (Cloudsmith), pose les sockets de contrôle, le statistics-channel et une configuration minimale.
2. Serveur déjà configuré : import (sections 4 et 5). Une ligne `include` ajoutée à `named.conf`, des sockets ajoutés à Kea s'ils manquent, rien d'autre n'est réécrit ; l'audit de sécurité propose ensuite son plan.
3. Docker : un `compose` qui lance le nœud à côté des images officielles ISC quand elles existent, sinon une image tout-en-un construite depuis les paquets de la distribution.

**Images officielles ISC (pages ouvertes le 24 octobre 2026)**

| Image | Où et quoi | Versions vues |
| --- | --- | --- |
| [`internetsystemsconsortium/bind9`](https://hub.docker.com/r/internetsystemsconsortium/bind9) | Docker Hub, « Official ISC BIND 9 Docker, based on Alpine image », maintenue par ISC « on a best-effort basis » | 9.18 (fin de vie), 9.20 (stable), 9.21 |
| [`docker.cloudsmith.io/isc/docker/kea-dhcp4`](https://cloudsmith.io/~isc/repos/docker/packages/), `kea-dhcp6`, `kea-dhcp-ddns` | Cloudsmith ISC, « public Docker container repository for open source (MPL 2.0) Kea DHCP images », un démon par image ; configuration montée dans `/etc/kea`, baux dans `/var/lib/kea` ([paquets ISC](https://kb.isc.org/docs/isc-kea-packages.md), [kea-docker](https://gitlab.isc.org/isc-projects/kea-docker)) | 3.2.1 (`latest`), 3.3.1 |

Il n'existe pas d'image ISC qui réunisse BIND et Kea, ni d'image séparée pour `kea-ctrl-agent`. Dans le `compose`, le nœud partage les volumes de configuration et le répertoire des sockets Kea avec les conteneurs ISC ; rndc et le statistics-channel passent par le réseau interne du `compose`. L'image tout-en-un embarque BIND, Kea et le nœud sous un superviseur, pour les cas sans image ISC.

**Licence**

Apache-2.0, décidé. UCM est sous AGPL-3.0 ; son auteur, qui est aussi celui de ce projet, relicencie en Apache-2.0 le code repris. Conséquences : en-tête `SPDX-License-Identifier: Apache-2.0` dans chaque fichier source, fichier `LICENSE`, fichier `NOTICE` qui nomme le projet, l'origine UCM du code repris et les bibliothèques tierces. BIND et Kea restent sous MPL-2.0 : les paquets deb et rpm ne les redistribuent pas, seule l'image tout-en-un les embarque, avec leur licence.

**Déploiement**

- Un nœud par serveur BIND / Kea, même paquet partout. Deux nœuds donnent la HA de l'interface ; un nœud supplémentaire sur une machine d'administration est possible mais pas nécessaire.
- Un nœud seul fonctionne aussi : un serveur avec BIND seul, Kea seul, ou les deux, sans pair.
- Prérequis posés par la phase 0 : clés TSIG et `update-policy` sur le primaire, sockets de contrôle Kea, statistics-channel local, fichiers inclus, enrôlement mTLS des pairs.
- Mises à jour par paquet ; le cache de séries se migre ou se reconstruit au démarrage ; la configuration de l'outil porte un numéro de schéma.
- Versionnage de la configuration (phase 4) : export périodique de `named.conf`, des zones (par AXFR) et de `config-get` Kea dans un dépôt git local, lecture seule, pour le diff et l'historique.

## 11. Questions ouvertes

Deux décisions bloquent la phase 0 : le parseur de `named.conf` et l'autorité de certification pour l'enrôlement mTLS. Le reste se tranche en cours de route. Les questions cochées sont tranchées par les commentaires en fin de document et reflétées dans le corps.

- [ ] Kea 3.x par les paquets ISC : Debian 13 est couvert (dépôts Cloudsmith kea-3-0 et kea-3-2, distribution trixie). Reste à fixer quand migrer les deux pairs (la HA exige la même version des deux côtés).
- [ ] Parseur de `named.conf` : l'écrire à partir de la grammaire publiée dans les sources de BIND, avec `named-checkconf -p` comme oracle de non-perte ? Aucune bibliothèque Python maintenue n'a été identifiée.
- [ ] Enrôlement mTLS : CA interne de l'outil par défaut, ou UCM quand il est présent ?
- [ ] Format du fichier de configuration de l'outil (TOML ou JSON) et politique de version du schéma.
- [ ] Docker : comment partager le socket de contrôle Unix des conteneurs Kea ISC avec le conteneur du nœud, sachant que leur README lance aussi un control agent ?
- [x] Pair standby : plus de question, le nœud local parle au socket Unix (section 5).
- [x] rndc et statistics-channel : locaux au nœud, ni SSH ni agent distant (section 4).
- [x] Hébergement : un nœud identique sur chaque serveur, répliqué (section 3).
- [ ] Stack : Flask reste le défaut, la question Flask ou FastAPI reste ouverte (section 10).
- [x] Licence : Apache-2.0, code repris d'UCM relicencié par son auteur (section 10).
- [ ] Nom du projet : Pelagos (paquet, dépôt, service et module en minuscules : pelagos).
- [x] `update-policy` : types fixés pour `ddi-admin` et `kea-ddns`, DHCID inclus (section 4).
- [x] Clé rndc : régénérée en hmac-sha256 par l'assistant d'audit en phase 0 (section 9).
- [ ] La configuration D2 lue ne déclare que la zone directe et l'inverse IPv4 : l'inverse IPv6 sans DDNS est-elle voulue ?
- [x] Réservations : dans la configuration de chaque pair, fixée par `config-write` ; pas de base d'hôtes partagée (section 6).
- [x] Statistics-channel sur le secondaire aussi : oui, une série par instance (section 4).
- [ ] Lire la catégorie `update` du journal de `named` pour les refus DDNS, ou se contenter des compteurs D2 ?
- [x] DHCPv6 : module optionnel, mêmes écrans, délégation de préfixe comprise (section 5).
- [x] Rétention des séries : table validée en section 6.
- [x] Palette : Pelagic remplace Deep Sea, `gray`, `purple` et `sunset` restent (section 8).
- [ ] Les `host_cmds` de Kea 3.x écrivent-ils dans la configuration en mémoire seulement ? Vérifier le couplage avec `config-write` avant la phase 3.
- [ ] Kea 2.6 en mode dégradé : jusqu'à quand le maintenir une fois les deux pairs en 3.x ?

12. Commentaires de moi:

- Il faut que ce logiciel soit générique, dans le sens ou il peut s'installer sans bind ou kea, et les installer lui meme a la suite.&#32;

* Qu'il soit capable de reprendre une conf existante de l'un ou l'autre.&#32;
* Qu'il soit multi os (deb et rpm)
* qu'on puisse livrer un docker capable d'utiliser les images officielles bind et ou kea dhcp s'il y a, sinon tout embarquer.
* qu'on puisse avoir cette ui de controle en ha lui aussi en cas de perte de l hote (genre 2 dashboards qui se sync automatiquement et quand l'un revient il se maj) sans sur ingénierie, garder les choses simples et sures
* qu'il mette a niveau les conf existantes en mode secure md5 -> sha256 minimum
* la configuration se fait au plus proche du logiciel: conf kea et bind pour eviter d'avoir a maintenir une base sql partagée ou autre et rendre le tout portable
* pour tout ce qui executeur tu prends la meilleure methode, la plus facile a utiliser pour le logiciel
* on essaie d'utiliser les outils fournis au possible, ex `kea-ctrl-agent`&#32;
* licence completement ouverte
* statistiques de chaque elements (chaque bind, chaque dhcp server)
* pour dhcpv6 le prendre en compte en mode optionnel
* qu'il puisse fonctionner simplement pour un element tout seul, bind ou kea ou les 2
* Rétention par défaut des séries dérivées (baux, serials, états HA). -> oui
* `update-policy` : tu choisis le mieux
* pour les themes garder les existant, ajouter des nouveaux dont un style PELAGIC : Ocean Mission Control UI
