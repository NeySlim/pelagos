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
9. Le système de design d'[Ultimate CA Manager (UCM)](https://github.com/NeySlim/ultimate-ca-manager) : thèmes existants gardés, nouveaux thèmes ajoutés.

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
- `update-policy` décidé : `grant ddi-admin zonesub A AAAA PTR CNAME TXT SRV MX NS CAA DHCID;` (exactement les types de l'éditeur de zone ; NS et CAA ajoutés en 0.1.2, l'audit élargit les règles plus anciennes) et `grant kea-ddns zonesub A AAAA PTR DHCID;`. DHCID est inclus pour `ddi-admin` : sans lui, l'outil ne peut pas nettoyer un nom laissé par un bail. Jamais SOA ni les types DNSSEC : ils restent à BIND.
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

- Authentification et RBAC repris d'UCM (`backend/auth`, `backend/security`) : mots de passe argon2, TOTP, WebAuthn (clés de sécurité et passkeys, ci-dessous), sessions, limitation de débit. Les utilisateurs et rôles sont dans la configuration répliquée : le même compte ouvre chaque nœud.
- Rôles minimaux : lecture, opérateur DNS, opérateur DHCP, administrateur. Un opérateur DNS ne voit pas les secrets Kea.
- Entre nœuds : HTTPS mTLS, certificats émis à l'enrôlement par le premier nœud (CA interne de l'outil) ou par UCM si une CA existe déjà. Un nœud inconnu est refusé ; l'enrôlement passe par un jeton à usage unique.
- Secrets chiffrés au repos dans la configuration de l'outil, clé maître hors du fichier, remise une fois à l'enrôlement, comme UCM.
- Audit en ajout seul, fichier JSONL répliqué : utilisateur, nœud, horodatage, requête envoyée (UPDATE, commande Kea, fichier écrit), réponse reçue, diff avant / après. Toute écriture a son retour arrière préparé.
- Chaque nœud n'écoute que sur le réseau d'administration, en HTTPS, derrière le même gunicorn TLS qu'UCM.
- Les données lues chez BIND et Kea (noms d'hôtes DHCP, TXT, `user-context`) sont traitées comme non fiables : échappées à l'affichage, jamais interprétées.

**Clés de sécurité et passkeys (point 66, 0.2.1)**

Reprise d'UCM (`backend/api/v2/webauthn.py`, `backend/services/webauthn_service.py`, `backend/auth/twofa_enforcement.py`) avec la bibliothèque `webauthn` (py_webauthn, BSD-3-Clause), adaptée au stockage de Pelagos.

- Plusieurs clés par utilisateur : nom (modifiable), date de création, nœud d'enregistrement, dernier usage, suppression. Les clés vivent dans l'enregistrement de l'utilisateur de `cluster.toml` (clé publique COSE, identifiant, transports, AAGUID, rpId) : répliquées, une clé enregistrée sur ns1 ouvre ns2. Le dernier usage et le compteur de signatures restent par nœud (comme `last_login`) : une connexion n'écrit jamais `cluster.toml`.
- Deux usages. Second facteur : après le mot de passe, un utilisateur qui a une clé doit la présenter (ou son code TOTP s'il en a un et que son rôle n'exige pas de clé). Passkey sans mot de passe : clé découvrable avec vérification de l'utilisateur (PIN ou biométrie), sans nom d'utilisateur saisi, donc sans énumération des comptes.
- Obligation par rôle : `auth.require_webauthn_roles` (ex. `["admin"]`). Un membre sans clé n'obtient qu'une session restreinte à l'enregistrement d'une clé ; un membre qui a une clé ne peut pas la remplacer par le TOTP ni supprimer sa dernière clé. `auth.require_totp` est aussi satisfait par une clé.
- rpId : le domaine commun des noms des nœuds (`web_url`), par exemple `example.lan` pour `ns1.example.lan` et `ns2.example.lan`, ou le réglage `auth.webauthn_rp_id`. Sans domaine commun, l'écran d'administration avertit : les clés ne valent alors que pour le nœud où elles sont enregistrées. Une adresse IP ne peut pas porter de clé (règle des navigateurs), HTTPS avec un certificat valide est obligatoire.
- TOTP et récupération locale conservés (Pelagos n'a pas de codes de secours) : l'administrateur retire les clés d'un utilisateur dans l'écran Utilisateurs, et `pelagos user remove-keys <nom>` le fait en local, comme `disable-totp`.
- Écrans : section « Clés de sécurité » du profil (ajout, renommage, suppression), bouton « Se connecter avec une passkey » et étape « clé de sécurité » à la connexion, colonne et action dans Administration > Utilisateurs, état du rpId et avertissement dans le même écran.

**Jetons d'API (point 70, 0.2.3)**

Depuis qu'un administrateur a une clé de sécurité, `POST /auth/login` répond `401 second_factor_required` et aucun script ne peut plus appeler l'API (contrôles après mise à jour, plans, supervision). Les jetons d'API rouvrent cet accès sans affaiblir la connexion interactive.

- Forme `pel_<id>_<secret>` : `id` de 16 caractères hexadécimaux (retrouve l'enregistrement), secret de 32 octets aléatoires. Seule l'empreinte SHA-256 du jeton entier est gardée, dans `cluster.toml [[api_tokens]]`, donc répliquée : un jeton créé sur ns1 marche sur ns2. Pas d'argon2 : un secret aléatoire de 256 bits ne se devine ni ne se casse hors ligne, un hachage lent coûterait à chaque requête sans rien protéger de plus ; l'empreinte empêche seulement qu'une copie de `cluster.toml` serve de jeton. Comparaison en temps constant. Le jeton n'est montré qu'une fois, à la création, et n'apparaît jamais dans une réponse, un journal ou l'audit.
- Usage : `Authorization: Bearer <jeton>`, sans cookie ni en-tête CSRF, non soumis à `auth.require_webauthn_roles`. Un jeton n'atteint ni `/auth/*` ni `/account/*` (sauf `GET /auth/session`) : il ne crée pas de jeton, ne change pas de mot de passe, n'enregistre pas de clé. Le WebSocket reste réservé à la session.
- Création depuis le profil ou l'API par un utilisateur connecté, avec une vérification fraîche de son second facteur : assertion de clé (cérémonie à usage unique, comme le second facteur de la connexion) ou code TOTP pour un utilisateur TOTP dont le rôle n'exige pas de clé. Sans second facteur utilisable, la création est refusée.
- Droits : un rôle (par défaut `viewer`, le rôle lecture seule) ou une liste de permissions, jamais plus larges que celles du créateur. À chaque appel, les droits du jeton sont croisés avec ceux de l'utilisateur à cet instant : un utilisateur qui perd un droit, est désactivé ou supprimé l'enlève à ses jetons (supprimer l'utilisateur supprime ses jetons).
- Expiration obligatoire (90 jours par défaut, `auth.api_token_default_days`, au plus `auth.api_token_max_days`), adresses sources autorisées facultatives (liste CIDR), révocation (suppression de l'enregistrement : la pierre tombale l'emporte partout). Alerte `api_token_expiry` avant l'échéance (`checks.api_token_warning_days`, critique à `checks.api_token_critical_days`), levée par le seul nœud de service.
- Dernier usage (nœud, heure, adresse) gardé par nœud dans `var/api_token_usage.json`, comme `last_login` : un appel n'écrit jamais `cluster.toml` et ne fait pas monter la version du cluster. Les écrans fusionnent les derniers usages de tous les nœuds.
- Audit : chaque appel par jeton est audité au nom de l'utilisateur avec le nom du jeton (`auth.token_call`) ; les lectures peuvent être exclues par `auth.api_token_audit_reads_enabled`, les écritures jamais. Création et révocation sont auditées. Un plan appliqué par jeton exige toujours `confirm: true`.
- Versions mélangées : un nœud 0.2.1 ou 0.2.2 ignore `[[api_tokens]]` (il ne l'efface pas, la fusion la rapporte) et ignore l'en-tête `Authorization` : un script qui l'appelle reçoit `401 unauthenticated`. Mettre à jour tous les nœuds avant de s'appuyer sur les jetons.
- Écrans : section « Jetons d'API » du profil (création, secret affiché une fois, révocation), Administration > Jetons d'API (tous les jetons, titulaire, droits, dernier usage, révocation), en anglais et en français.

### Garde des permissions (point 79)

En production (0.2.4), un abonnement RPZ échouait à l'application : « cannot create zone directory
/etc/bind/cache/pelagos: [Errno 1] Operation not permitted ». Cause : `RestrictSUIDSGID=yes` dans les
unités. Le filtre seccomp refuse tout `mkdir` ou `chmod` dont le mode porte S_ISGID ; le code créait
les dossiers de zones en `0o2775`, donc aucune unité packagée ne pouvait en créer un, même dans un
dossier 2775 bind:bind inscriptible. Le labo ne l'avait pas vu : l'importeur crée
`/var/cache/bind/pelagos` en root et la synchro RPZ créait `rpz/` sans setgid avant le plan.
Décisions :

- Garder `RestrictSUIDSGID`. Les dossiers sont créés par `mkdir(2)` en 0777 sous umask 002 : le
  noyau propage le setgid du parent sans passer par le filtre. Aucun mode avec S_ISGID ou S_ISUID
  dans le code des unités (un test unitaire le vérifie) ; l'installateur, en root, n'est pas filtré.
- Contrôle au plan, jamais à l'apply : chaque plan est vérifié sur chaque nœud cible, dans le
  contexte réel de l'unité. Le choix : évaluer dans le service en cours (le processus web pour le
  nœud local, le collecteur d'un pair via `/repl/v1/plans/preflight`), qui est l'unité, avec son
  utilisateur, ses groupes, `ProtectSystem`, `ReadWritePaths` et ses filtres. Chaque sonde refait
  l'opération de l'écrivain (même fonction, mêmes bits de mode) sur un nom jetable, car `access(2)`
  aurait répondu « oui » en production. Les chemins viennent du code qui écrit
  (`permission_targets`, le même rendu que l'apply), pas d'une liste à part.
- Échec : plan refusé, constat traduit (en/fr) par nœud et chemin : propriétaire, groupe, mode, ce
  qui manque et la commande exacte (`install -d -o bind -g bind -m 2775 /etc/bind/cache/pelagos`).
  Les erreurs d'apply qui portent un errno brut sont traduites aussi.
- En continu : le collecteur refait le contrôle au démarrage (donc après chaque mise à jour) puis
  toutes les 10 minutes ; alerte `path_not_writable` (warning) par nœud et chemin, résolue d'elle-même ;
  carte « Permissions » par nœud dans l'écran d'audit de sécurité.
- Remédiation : constat `path_access` de l'audit, appliqué par l'assistant privilégié : création du
  premier dossier manquant en 2775 bind:bind ou ajout de g+w sur un dossier du groupe du moteur,
  annulé si une étape échoue. Jamais d'élargissement silencieux, jamais de chown d'un dossier
  existant, jamais le `directory` de named lui-même, seulement sous les arborescences des moteurs.
- Le paquet règle les permissions : `pelagos permissions ensure` dans le postinst (installation et
  mise à jour, idempotent) crée les dossiers manquants à partir des mêmes cibles (le `directory`
  effectif de named compris) et donne au groupe Kea les fichiers Kea que le service doit lire (point
  67). La garde au plan reste pour ce qui change après l'installation.
- `deploy-prod.sh` lance `pelagos permissions check --unit pelagos-collector.service` avant et après
  la mise à jour de chaque nœud (unité transitoire qui copie le bac à sable de l'unité) et s'arrête
  sur un chemin non inscriptible ; `pelagos install` et `pelagos import` finissent par la même garde.

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

- [ ] Kea 3.x par les paquets ISC : Debian 13 est couvert (dépôts Cloudsmith kea-3-0 et kea-3-2, distribution trixie). Reste à fixer quand migrer les deux pairs (la HA exige la même version des deux côtés) : migration spécifiée en 13.4.
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
- [ ] Kea 2.6 en mode dégradé : jusqu'à quand le maintenir une fois les deux pairs en 3.x ? Défaut proposé en 13.11.

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

## 13. Sixième passe : fonctions nouvelles (points 56 à 63)

Trois fonctions de priorité 1 (points 56, 57 et 58 du relevé de production, 13.1 à 13.3, livrées en 0.2.0), puis les fonctions 59 à 62 (13.4 à 13.7 ; le point 63 est retiré, 13.8), spécifiées ici avant tout code. Les lots sont en 13.9 et 13.10, les questions des points 59 à 63 avec leur défaut en 13.11. Les contrats techniques (schémas, routes exactes, champs) iront dans `docs/architecture.md` par le premier lot de chaque fonction, avec une entrée dans `docs/contracts-changes.md` ; ce chapitre fixe le besoin, les écrans, les décisions et le découpage.

Règles communes :

- Une modification d'un moteur (BIND, Kea, D2) passe par un plan : aperçu, validations, confirmation, application nœud par nœud, retour arrière (architecture, sections 6 et 7). Un réglage propre à Pelagos (`cluster.toml`) suit le modèle des réglages existants : écrit par `update_cluster`, répliqué, audité avec l'état d'avant, donc réversible, sans plan.
- Nouveaux domaines de réglages : `notifications`, `archives`, `ddns`, puis `resolver`, `updates`, `ipv6` (ajoutés à `DOMAINS` du registre, nommage de la section 10 de l'architecture). Les seuils qui lèvent une alerte vont dans `[settings.checks]`. Les entrées écrites par un écran dédié (canaux, destinations, rôles DNS) sont refusées par `PUT /admin/settings`, comme celles du RPZ.
- Secrets dans `cluster.toml [secrets]`, chiffrés par la clé maître, jamais renvoyés par l'API (booléens « défini »), masqués dans les plans, l'audit et les journaux.
- Chaque nouvelle alerte a sa clé de message (`alert.*`) en anglais et en français, et figure dans la table des alertes de la section 15 de l'architecture.
- Tests : les trois niveaux d'AGENTS.md. Le niveau unitaire n'ouvre aucun réseau : les transports sont injectés et remplacés par des faux en mémoire.
- Le « nœud de service » est celui de la décision 1 du 13.1 (premier nœud en ligne de l'ordre d'envoi) : il fait aussi ce qui ne doit être fait qu'une fois dans le cluster (vérification des versions disponibles).

### 13.1 Notifications sortantes (point 56)

**Besoin**

Une alerte n'est vue que si quelqu'un ouvre l'interface : en production la HA Kea est restée `terminated` plusieurs jours sans que personne le sache. Pelagos doit pousser les alertes vers les canaux que l'administrateur lit déjà (e-mail, téléphone, domotique), sans doublon dans le cluster, sans tempête de messages, et continuer à prévenir quand le nœud qui envoie d'habitude est justement celui qui est tombé.

**Ce qui existe et sur quoi on s'appuie**

- Chaque collecteur évalue ses alertes et les garde dans son cache SQLite (`collector/alerts.py`, `AlertStore.reconcile`) ; l'identifiant d'une alerte est stable (genre, nœud, sujet), donc le même d'un passage à l'autre.
- La vue de cluster existe déjà : l'API agrège les alertes de chaque nœud par l'action de pair `alerts.list` (`services/alerts_service.py`), fusionne les copies d'une alerte de cluster et signale les nœuds injoignables (`unavailable`).
- Les acquittements et les exceptions sont répliqués (audit `alert.ack`, `[[exceptions]]`) : une alerte acquittée ou exceptée n'a pas à être rappelée.
- Le réplicateur sait quels pairs sont hors ligne (`Replicator.offline_peers()`, 3 sondages manqués).

**Décisions**

1. Un seul expéditeur à la fois, sans élection : chaque collecteur fait tourner le répartiteur, mais seul envoie le premier nœud de l'ordre d'envoi (par défaut l'ordre d'enrôlement de `[[nodes]]`, réglable dans l'écran) parmi ceux que ce collecteur voit en ligne. Quand l'expéditeur tombe, le suivant le constate au bout de 3 sondages de pairs (90 s par défaut) et prend le relais. En cas de coupure réseau entre nœuds, chaque côté se croit premier et envoie : un doublon vaut mieux qu'un silence, et c'est dit dans l'écran.
2. La file est dérivée, pas répliquée : un événement à envoyer est une transition d'alerte (ouverte, aggravée, résolue, rappel) qui n'a pas encore d'entrée d'audit `notify.sent` pour ce canal. Chaque envoi réussi écrit une entrée d'audit par lot (canal, identifiants d'alertes, événements, nœud expéditeur), répliquée comme le reste. Un nouvel expéditeur relit ces entrées des 7 derniers jours pour savoir ce qui est déjà parti : rien n'est perdu au relais, au pire un lot est renvoyé une fois (au moins une fois, jamais zéro). La file locale (`/var/lib/pelagos/notify/`, 0700) ne garde que l'état des nouvelles tentatives.
3. Événements : `opened` (alerte nouvelle au-dessus du seuil du canal), `escalated` (gravité en hausse), `resolved` (si le canal le demande), `reminder` (toujours ouverte, non acquittée, après le délai de rappel), `test`. Une alerte ouverte puis résolue dans la fenêtre de regroupement ne part pas. Un délai de confirmation (défaut 60 s, 0 pour `critical`) évite les alertes d'une seule passe.
4. Regroupement : un message par canal et par fenêtre (`group_seconds`, défaut 60 s) qui liste tous les événements de la fenêtre, triés par gravité, avec le compte des alertes encore ouvertes. Plafond par canal (`messages_max_per_hour`, défaut 30) : au-delà, un seul message « N événements de plus, voir l'interface ».
5. Heures calmes par canal (début, fin, fuseau IANA, jours) : les événements retenus partent en un résumé à la fin de la période, sans ceux résolus entre-temps ; `critical` passe quand même sauf si le canal le refuse.
6. Silence global (« maintenance jusqu'à ») réglable depuis l'écran, avec motif obligatoire et fin obligatoire (24 h au plus), audité ; à la fin, un résumé des alertes encore ouvertes part.
7. Langue par canal (français ou anglais) : le rendu utilise les clés de message (`title_message`) avec les catalogues de l'interface, empaquetés côté serveur (`pelagos/data/i18n/<langue>.json`, produits par une cible `make` à partir des fichiers du frontend, un seul jeu de traductions).
8. Pas de plan : un canal est un réglage de Pelagos, il ne touche aucun moteur.

**Canaux** (API vérifiées le 2026-10-28)

| Canal | Envoi | Authentification | Remarques |
| --- | --- | --- | --- |
| E-mail (SMTP) | `smtplib`, texte brut (HTML plus tard) | STARTTLS (587) ou TLS implicite (465), identifiant et mot de passe optionnels | Sans TLS seulement vers une adresse de bouclage, avec avertissement ; destinataires multiples ; sujet `[Pelagos] 2 critical, 1 warning : ...` |
| ntfy | JSON `POST` sur la racine du serveur, champs `topic`, `message`, `title`, `tags`, `priority` (1 à 5), `click` ([docs ntfy, Publish as JSON](https://docs.ntfy.sh/publish/)) | `Authorization: Bearer tk_...` ou Basic | Gravité vers priorité : critical 5, warning 4, info 3, résolution 2 ; `click` vers la page de l'alerte ; message limité à 4 096 octets, au-delà ntfy en fait une pièce jointe |
| Gotify | `POST /message`, JSON `title`, `message`, `priority`, `extras` ([spec Gotify](https://github.com/gotify/server/blob/master/docs/spec.json)) | jeton d'application dans `X-Gotify-Key` (jamais en paramètre d'URL) | Priorités réglables, défaut 8, 5, 2 |
| Matrix | `PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}`, `msgtype` `m.text`, `format` `org.matrix.custom.html` ([spec Matrix v1.11](https://spec.matrix.org/v1.11/client-server-api/)) | `Authorization: Bearer` d'un compte robot | `txnId` = identifiant du lot et du canal : un renvoi est idempotent côté serveur, deux canaux sur le même robot ne se confondent pas |
| Webhook générique | `POST` JSON, schéma `pelagos.notification.v1` (ci-dessous) | en-têtes libres, signature HMAC-SHA256 optionnelle | Aucune redirection suivie ; `X-Pelagos-Delivery` = identifiant du lot pour dédoublonner |
| Home Assistant | préréglage du webhook : `POST /api/webhook/<webhook_id>`, charge lue dans `trigger.json` ([HA, Webhook trigger](https://www.home-assistant.io/docs/automation/trigger/)) | l'identifiant du webhook est le secret | HA n'accepte par défaut que le réseau local (`local_only`), ce qui convient ; l'identifiant est stocké comme un secret |

Charge du webhook (v1, champs ajoutés sans changer de version) :

```json
{"schema": "pelagos.notification.v1", "id": "<ULID du lot>", "cluster_id": "...", "sent_at": "2026-10-28T10:00:00Z",
 "sender": {"node_id": "...", "name": "ns1"}, "reason": "events" | "digest" | "test",
 "events": [{"event": "opened" | "escalated" | "resolved" | "reminder",
             "alert": {"id", "kind", "severity", "state", "node_id", "node_name", "engine", "subject",
                       "title", "title_message", "first_seen", "last_seen", "resolved_at", "url"}}],
 "open": {"critical": 1, "warning": 3, "info": 0}}
```

Signature : `X-Pelagos-Timestamp: <secondes Unix>` et `X-Pelagos-Signature: sha256=<hex>` = HMAC-SHA256 du secret sur `<timestamp>.<corps>` ; le récepteur refuse un horodatage de plus de 5 minutes.

**Écrans**

- Administration, Notifications : en tête, l'expéditeur actuel (nœud, depuis quand), le silence en cours, le nombre d'événements en attente ou en échec. Puis une carte par canal : type, nom, état (ok, en échec depuis, désactivé), dernier envoi, boutons Tester, Modifier, Désactiver.
- Formulaire de canal (`FormModal`) : champs propres au type ; filtres (gravité minimale, défaut `warning` ; genres inclus ou exclus en `FilterChips`, défaut sans les incohérences `info` ni `ha_transition` ; nœuds ; moteurs) ; regroupement, rappel (défaut 12 h, 0 = jamais), résolution oui ou non, délai de confirmation, heures calmes, langue. « Tester » envoie un message réel depuis le nœud courant avant même l'enregistrement et affiche la réponse du service.
- Historique : table paginée des lots envoyés ou en échec (lue dans l'audit `notify.*`), filtre par canal, détail du lot.
- Ordre d'envoi : liste ordonnable des nœuds.
- Page Alertes : dans le détail d'une alerte, « notifiée à 10:32 par ntfy, e-mail » ; bannière quand un silence est actif.

**API** (préfixe `/api/v1`, conventions de la section 17)

| Méthode, chemin | Permission | Requête | Réponse |
| --- | --- | --- | --- |
| `GET /admin/notifications` | `admin:notifications` | | `{"channels": [Channel], "settings", "sender": {"node_id","since","order"}, "mute": {...}|null, "queue": {"pending","failing"}}` (secrets en booléens) |
| `POST /admin/notifications/channels` | `admin:notifications` | `Channel` sans `id`, `secrets`: `{name: str}` | `201 Channel` |
| `PUT /admin/notifications/channels/{id}` | `admin:notifications` | partiel ; `secrets`: `{name: str|null}` (`null` efface) | `Channel` |
| `DELETE /admin/notifications/channels/{id}` | `admin:notifications` | | `204` |
| `POST /admin/notifications/test` | `admin:notifications` | `{"channel_id"}` ou un `Channel` non enregistré (`scope` nomme les secrets déjà stockés) | `{"ok","node_id","duration_ms","status"?,"error"?}` |
| `PUT /admin/notifications/order` | `admin:notifications` | `{"node_ids": [...]}` | `{"order"}` |
| `PUT /admin/notifications/mute` | `admin:notifications` | `{"until","comment"}` ; `DELETE` lève le silence | `{"mute"}` |
| `GET /admin/notifications/history?channel_id=&result=&from=&to=&page=&per_page=` | `admin:notifications` | | paginé `{"id","ts","channel_id","node_id","events","result","error"}` |

Nouvelle permission `admin:notifications` (dans le rôle administrateur). Audit : `admin.notify.add|replace|delete|op` pour les réglages, `notify.sent` et `notify.failed` pour les envois (sans corps ni secret). Événement WebSocket `system` / `notify` quand un canal change d'état.

**Réglages**

`[settings.notifications]` : `dispatch_enabled` (vrai), `group_seconds` (60), `confirm_seconds` (60), `messages_max_per_hour` (30), `retry_max_hours` (24), `send_timeout_seconds` (15). Écrits par l'écran : `notifications.channels` (liste de tables : `id`, `type`, `name`, `enabled`, `params`, `filters`, `schedule`, `language`), `notifications.order`, `notifications.mute`. Secrets : `notify/<id du canal>/<password|token|webhook_id|hmac_secret>`. Seuil dans `[settings.checks]` : `notification_failure_warning_minutes` (30).

**Plusieurs nœuds**

L'expéditeur lit la vue de cluster par `alerts.list` (même code que l'API, déplacé dans un module partagé par l'API et le collecteur). Un nœud injoignable n'empêche pas l'envoi : ses alertes manquent, et le `peer_offline` levé par les autres est justement ce qu'on veut recevoir. Une entrée `notify.sent` qui arrive par la réplication pendant qu'un lot est en attente sur un autre nœud annule ce lot. Les nœuds d'une version antérieure n'envoient rien : seule la version qui connaît le répartiteur envoie.

**Sécurité**

- Vérification TLS toujours active ; CA supplémentaire réglable par canal (PEM), pour un ntfy ou un Gotify signés par une CA privée.
- Schémas `https` et `http` seulement ; `http` avec un secret affiche un avertissement ; pas de redirection suivie ; délai d'envoi borné ; corps de réponse lu sur 4 Kio au plus.
- Le contenu ne porte jamais de détail brut d'alerte : titre rendu, nœud, moteur, sujet, lien. Les noms venus des moteurs (noms d'hôtes DHCP) sont tronqués et échappés (HTML de Matrix et du futur e-mail HTML).
- Seul `admin:notifications` lit ou change un canal ; « Tester » est limité à 6 envois par minute par utilisateur.

**Pannes**

| Panne | Comportement |
| --- | --- |
| Service injoignable, 5xx, délai dépassé | Nouvel essai à 30 s, puis délai doublé jusqu'à 30 min, pendant `retry_max_hours` ; puis abandon audité (`notify.failed`) |
| 4xx (jeton refusé, sujet inconnu) | Pas de nouvel essai automatique ; canal marqué en échec |
| Canal en échec depuis le seuil | Alerte `notification_failed` (warning, sujet `notify:<id>`), envoyée par les autres canaux |
| Expéditeur tombé | Relais au suivant après `offline_peers`, relecture de l'audit, renvoi de ce qui n'est pas marqué envoyé |
| Coupure entre nœuds | Les deux côtés envoient ; doublons possibles, signalés dans l'écran |
| Collecteur redémarré | État des tentatives relu dans `/var/lib/pelagos/notify/`, événements recalculés depuis le cache et l'audit |
| Horloge du nœud fausse | Les heures calmes suivent l'horloge locale ; `clock_unsynchronized` existe déjà |

**Tests**

- Unitaires : choix de l'expéditeur (ordre, pairs hors ligne, coupure) ; dérivation des événements depuis deux états de cluster successifs ; regroupement, annulation d'une alerte brève, délai de confirmation, aggravation ; rappels arrêtés par l'acquittement et l'exception ; heures calmes avec fuseau et changement d'heure (`zoneinfo`) ; plafond horaire ; relais (relecture de `notify.sent`, pas de doublon) ; rendu de chaque canal (corps, en-têtes, priorités, HMAC, `txnId`) contre des transports factices ; masquage des secrets dans l'audit et les erreurs ; réglages au registre ; API (permissions, secrets jamais renvoyés).
- Démons : deux collecteurs réels (fixture `test_n_nodes_daemons.py`) et un récepteur HTTP local : une alerte réelle (`daemon_down` en arrêtant named) donne exactement un lot ; arrêt du collecteur expéditeur, relais par l'autre, aucun doublon.
- Labo : sur la VM Docker du labo, conteneurs ntfy, Gotify, Mailpit (SMTP) et un récepteur de webhook ; scénario `tests/lab/test_notify_lab.py` : panne HA provoquée (arrêt de Kea sur un nœud), réception sur chaque canal, résolution, arrêt de la VM expéditrice et relais. Matrix (Conduit) et Home Assistant en option dans le même scénario.

### 13.2 Sauvegardes planifiées et restauration (point 57)

**Besoin**

Perdre un nœud ne doit pas faire perdre la configuration de BIND, de Kea et de Pelagos. Aujourd'hui seules existent les sauvegardes du pipeline d'écriture (`/var/lib/pelagos/backups/<engine>/`, une par écriture, sur le nœud lui-même, purgées après `retention.backups_days`) : elles disparaissent avec le disque et ne couvrent ni les zones dynamiques, ni les fichiers de l'utilisateur, ni l'état de Pelagos. Il faut une archive régulière, chiffrée, copiée hors du nœud, vérifiée, et une restauration depuis l'interface ou, pour un nœud perdu, depuis la ligne de commande.

Vocabulaire : « archive » pour cette fonction (code `pelagos.archives`, réglages `[settings.archives]`, dossier `/var/lib/pelagos/archives/`), pour ne pas confondre avec les sauvegardes du pipeline. L'interface dit « Sauvegardes ».

**Contenu d'une archive** (une par nœud et par passage)

| Partie | Contenu | Source |
| --- | --- | --- |
| BIND, configuration | `named.conf` et tout fichier inclus (lus par le parseur, comme l'arbre de l'éditeur avancé), fichiers de clés (TSIG, rndc), `pelagos/*.conf` | fichiers |
| BIND, zones primaires dynamiques | contenu de chaque zone au format texte, pris par AXFR avec la clé de lecture (instantané cohérent à un serial, sans `freeze` qui bloquerait les mises à jour) | AXFR local |
| BIND, zones primaires statiques | fichier de zone tel quel | fichier |
| BIND, DNSSEC | dossier des clés (`key-directory`, fichiers `K*.key`, `.private`, `.state`) quand une `dnssec-policy` est active | fichiers |
| Kea | `kea-dhcp4.conf`, `kea-dhcp6.conf`, `kea-dhcp-ddns.conf` et leurs inclusions, fichiers de secrets de D2, empreinte `config-hash-get` | fichiers, socket |
| Kea, baux | fichiers memfile (`kea-leases4.csv`, `.6`) si `include_leases_enabled` | fichiers |
| Pelagos | `node.toml`, `cluster.toml`, `audit.jsonl`, `pki/`, `master.key`, `tls/`, état du certificat web | fichiers |
| Manifeste | `manifest.json` : nœud, horodatage, versions (Pelagos, BIND, Kea), moteurs, chemin, mode, propriétaire et sha256 de chaque fichier, serial de chaque zone, fichiers illisibles | |

Les copies secondaires, le cache de séries et les listes RPZ ne sont pas archivés : ils se reconstruisent. Les zones secondaires reviennent par transfert.

**Format et chiffrement**

- `tar` compressé par gzip (bibliothèque standard), chiffré au format age v1 avec un destinataire X25519 ([spécification age v1](https://age-encryption.org/v1), consultée le 2026-10-28 : en-tête avec une strophe X25519, charge découpée en morceaux de 64 Kio chiffrés par ChaCha20-Poly1305). Implémenté avec `cryptography` (déjà une dépendance), aucune dépendance nouvelle ; interopérable avec l'outil `age` (paquet Debian `age` 1.2.1 dans trixie), ce qui permet d'ouvrir une archive sans Pelagos en cas de désastre.
- Fichier `<nœud>-<horodatage>.tar.gz.age` et, à côté, `.sha256` du fichier chiffré : l'intégrité se vérifie sans la clé.
- Clés de l'archive (décision 3) : chaque archive est chiffrée pour plusieurs destinataires age. Le premier est l'identité du cluster : Pelagos génère une identité X25519 à la mise en place, la clé publique (`age1...`) est dans `cluster.toml`, l'identité privée dans `[secrets]` (`archives/identity`), chiffrée par la clé maître, pour que n'importe quel nœud puisse restaurer ; elle est proposée au téléchargement une fois, avec l'avertissement « sans elle, la perte de tout le cluster est irrécupérable ». S'y ajoutent, en option, les clés publiques de l'administrateur (`archives.recipients`), dont Pelagos ne garde aucune identité : une archive s'ouvre alors aussi hors du cluster, et la restauration accepte de déposer l'une de ces identités. L'archive contient `master.key` et `ca.key` : elle n'est donc jamais stockée en clair, nulle part.

**Destinations**

| Destination | Mécanisme | Remarques |
| --- | --- | --- |
| Local | `/var/lib/pelagos/archives/local/`, les `local_keep_count` dernières | Toujours active ; sert de tampon si la destination distante échoue |
| Autre nœud du cluster | `POST /repl/v1/archives` en mTLS, rangée chez le pair dans `/var/lib/pelagos/archives/peers/<nœud d'origine>/` | Défaut dès qu'il y a deux nœuds ; couvre la perte d'un nœud, pas celle du site |
| Dossier monté | un chemin local que l'administrateur monte lui-même (NFS, SMB/CIFS par fstab ou automount systemd) | Pelagos ne monte rien et ne garde aucun mot de passe SMB ; il vérifie que le chemin est un point de montage et inscriptible |
| SFTP | client OpenSSH (`sftp -b`), clé privée dédiée stockée en secret, empreinte de la clé d'hôte épinglée | Pas de dépendance Python nouvelle |
| S3 compatible | plus tard (décision 2) : client minimal écrit à la main (signature v4, PUT, GET, LIST), sans `boto3` | Pas dans la première version |

Chaque destination a sa rétention : `keep_daily_count` (7), `keep_weekly_count` (4), `keep_monthly_count` (6), appliquée par le nœud qui écrit ; un pair applique aussi celle des archives qu'il reçoit.

**Planification**

Le collecteur de chaque nœud lance son archive à l'heure réglée (`start_time`, défaut 03:15 heure locale) décalée de `stagger_minutes` par rang du nœud, puis toutes les `interval_hours`. Le passage prend brièvement le verrou du moteur (section 6 de l'architecture) le temps de lire les fichiers de Kea et de BIND, pour ne pas archiver une écriture à moitié faite ; l'AXFR se fait hors verrou. Les fichiers que l'utilisateur `pelagos` ne peut pas lire passent par une opération en lecture seule de l'assistant privilégié (`pelagos helper`, liste fermée de chemins tirée de la disposition du système), sinon ils sont listés dans le manifeste et l'archive est marquée incomplète. Après l'envoi, l'archive est relue sur la destination et sa somme comparée (`verify_enabled`). Tous les `test_restore_days` jours, une restauration à blanc ouvre la dernière archive dans un dossier temporaire et passe `named-checkconf`, `named-checkzone` et `kea-dhcp4 -t` / `kea-dhcp6 -t` / `kea-dhcp-ddns -t` dessus.

**Restauration**

Trois modes, du plus courant au plus rare :

1. Restauration partielle depuis l'interface, sur un nœud qui tourne. L'administrateur choisit une archive, puis ce qu'il veut reprendre ; Pelagos montre le diff avec l'état actuel et construit un plan composite (scope `restore`, exécuté comme un job, une partie par moteur) :
   - fichiers gérés par Pelagos (`pelagos/*.conf`) : pipeline d'écriture, `named-checkconf`, `rndc reconfig`, retour arrière ;
   - contenu d'une zone dynamique : diff entre l'instantané et la zone actuelle, appliqué par UPDATE signé (`ddi-admin`, par lots), donc dans les types que `update-policy` autorise ; SOA et types DNSSEC ne sont jamais rejoués ; un type refusé est signalé avant l'application ;
   - zone entière en remplacement (option, pour une zone corrompue) : `rndc freeze`, remplacement du fichier, suppression du journal, `rndc thaw`, en mode maintenance explicite ;
   - Kea et D2 : `config-test` puis `config-set` et `config-write` par les plans existants (`plan_config_replace`), secrets de D2 scellés comme aujourd'hui ; pour une configuration partagée par la HA, la partie du pair est proposée dans le même plan ;
   - réglages de Pelagos : sections choisies de `cluster.toml` (réglages, exceptions, rôles, utilisateurs, canaux, RPZ), écrites par `update_cluster` donc répliquées ; l'audit de l'archive est fusionné par identifiant (sans risque, en ajout seul) ;
   - fichiers de l'utilisateur (`named.conf`, `named.conf.options`) : seulement sur case cochée explicitement, par le pipeline d'écriture, avec double confirmation, car Pelagos ne les réécrit jamais autrement.
   Chaque partie a son retour arrière (sauvegarde du pipeline, UPDATE inverse, configuration Kea capturée, valeurs d'avant de `cluster.toml`).
2. Restaurer les moteurs d'un nœud perdu sur un nœud neuf : le nœud neuf est enrôlé normalement (nouvelle identité), puis « Restaurer depuis l'archive de ns2 » reprend les fichiers BIND et Kea de l'ancien nœud (archive lue chez le pair qui la garde) ; Pelagos signale les adresses de l'ancien nœud présentes dans les configurations (`listen-on`, HA, D2) pour qu'on les adapte avant d'appliquer ; l'ancien nœud est ensuite retiré du cluster.
3. Reconstruction à l'identique, en ligne de commande, sur une machine vierge : `pelagos restore --archive <fichier> --identity <fichier> [--only bind,kea,pelagos] [--dry-run]` (root) remet `node.toml`, la PKI, la clé maître, les fichiers des moteurs, les zones (écrites en texte, journaux supprimés) et les baux, avant le premier démarrage des services ; le nœud revient avec son identité, se resynchronise avec ses pairs et reprend sa place. La procédure est écrite dans la documentation d'exploitation et jouée au labo.

**Écrans**

- Administration, Sauvegardes : par nœud, dernière archive réussie (date, taille, serials, complète ou non), prochaine, dernier échec ; bouton « Sauvegarder maintenant ».
- Destinations : liste, formulaire par type, « Tester » (écriture, relecture, suppression d'un fichier témoin).
- Clé : clé publique affichée, état de l'identité (gardée par le cluster ou non), téléchargement unique, rotation (les anciennes archives restent lisibles avec l'ancienne identité, gardée tant qu'une archive en dépend).
- Archives : table filtrable par nœud et destination, détail (manifeste), téléchargement (audité).
- Restaurer : assistant en trois étapes (archive, choix des parties avec le diff de chacune, aperçu du plan) puis la progression du job, comme les plans d'installation.

**API**

| Méthode, chemin | Permission | Requête | Réponse |
| --- | --- | --- | --- |
| `GET /admin/archives` | `admin:archives` | | `{"settings","recipients","identity": {"stored"},"destinations","nodes": [{"node_id","last_success","last_error","next_run","running","complete"}]}` |
| `POST`, `PUT`, `DELETE /admin/archives/destinations[/{id}]` | `admin:archives` | destination, `secrets` | destination / `204` |
| `POST /admin/archives/destinations/test` | `admin:archives` | `{"destination_id"}` ou une destination non enregistrée | `{"ok","node_id","error"?}` |
| `POST /admin/archives/run` | `admin:archives` | `{"node_ids"?}` | `202 Job` |
| `GET /admin/archives/list?node_id=&destination_id=&page=&per_page=` | `admin:archives` | | paginé `{"id","node_id","created_at","size","sha256","destinations","complete","versions","verified_at"}` |
| `GET /admin/archives/{id}/download` | `admin:archives` | | flux `application/octet-stream` (fichier chiffré), audité |
| `POST /admin/archives/upload` | `admin:archives` | multipart : archive venue d'ailleurs | l'archive inscrite |
| `POST /admin/archives/{id}/inspect` | `admin:archives` | `{"identity"?}` | `{"manifest","parts": [{"id","engine","node_id","files","diff_summary"}]}` |
| `POST /admin/archives/{id}/restore/plan` | `admin:archives` plus l'écriture de chaque partie | `{"target_node_id","parts": [...],"identity"?,"include_user_files"?}` | `Plan` (scope `restore`, `requires_confirmation`), appliqué par `POST /plans/{id}/apply` en `202 Job` |
| `POST /admin/archives/identity` | `admin:archives` | `{"op": "generate"|"rotate"|"add_recipient"|"remove_recipient"|"prune_retired","recipient"?,"label"?,"password"?}` | `{"recipients","identity"?}` (l'identité du cluster une seule fois) |
| `PUT /admin/archives/settings` | `admin:archives` | réglages partiels de `[settings.archives]` | `{"settings"}` ; planification refusée sans destinataire |

Réplication : `POST /repl/v1/archives` (dépôt, taille bornée par `max_archive_mb`), `GET /repl/v1/archives?origin=` (liste), `GET /repl/v1/archives/<id>` (lecture). Nouvelle permission `admin:archives`. Nouveau scope de plan `restore`. Audit : `admin.archive.*`, `archive.create`, `archive.restore.apply|rollback`.

**Réglages**

`[settings.archives]` : `schedule_enabled` (faux tant qu'aucune clé n'existe), `start_time` (`"03:15"`), `interval_hours` (24), `stagger_minutes` (15), `keep_daily_count` (7), `keep_weekly_count` (4), `keep_monthly_count` (6), `local_keep_count` (3), `include_leases_enabled` (vrai), `verify_enabled` (vrai), `test_restore_days` (7, 0 = jamais), `max_archive_mb` (512). Écrits par l'écran : `archives.destinations`, `archives.recipients`. Secrets : `archives/identity`, `archives/dest/<id>/ssh_key`. Seuils dans `[settings.checks]` : `archive_stale_factor` (2 : alerte quand la dernière archive réussie a plus de 2 intervalles), `archive_failures_critical_count` (3).

Alertes : `archive_failed` (warning, critical après le nombre d'échecs consécutifs ; sujet `archive:<destination>`), `archive_stale` (warning ; sujet `archive:last`), `archive_incomplete` (info ; fichiers illisibles listés).

**Plusieurs nœuds**

Chaque nœud archive ce qu'il porte ; `cluster.toml` et l'audit, identiques partout, sont dans chaque archive (peu de place, et n'importe quelle archive suffit à refaire le cluster). Le décalage `stagger_minutes` évite deux AXFR et deux envois en même temps. Un nœud garde les archives de ses pairs : la page liste aussi celles d'un nœud absent, lues chez qui les détient.

**Sécurité**

- Archives toujours chiffrées avant de quitter la mémoire du processus (le tar n'est jamais écrit en clair sur disque) ; fichiers 0600, dossiers 0700.
- Identité gardée par le cluster : chiffrée par la clé maître comme les autres secrets ; son téléchargement demande le mot de passe de l'utilisateur et est audité.
- SFTP : empreinte de la clé d'hôte obligatoire, pas de `StrictHostKeyChecking=no` ; clé dédiée, à restreindre côté serveur (`ForceCommand internal-sftp`, chroot), exemple dans la documentation.
- Restauration : `requires_confirmation`, permission d'écriture de chaque partie en plus de `admin:archives`, aucun secret dans l'aperçu (secrets masqués comme dans les plans).

**Pannes**

| Panne | Comportement |
| --- | --- |
| Destination injoignable | Archive gardée en local, nouvel essai au passage suivant, `archive_failed` |
| Disque plein | Passage annulé avant écriture si l'espace libre est sous la taille de la dernière archive plus 10 % ; `disk_space` existe déjà |
| Démon arrêté | Fichiers archivés quand même ; zones dynamiques prises dans le fichier et le journal (signalé) ; archive marquée incomplète |
| Somme différente à la relecture | Archive distante supprimée, nouvel essai, alerte |
| Restauration qui échoue sur une partie | Retour arrière de la partie puis des précédentes (plans composites existants) |
| Identité perdue | Archives illisibles : l'écran le dit tant qu'aucune identité n'est gardée ni confirmée téléchargée |

**Tests**

- Unitaires : format age (vecteurs de test officiels de la suite CCTV d'age, aller-retour, morceaux de 64 Kio, archive tronquée refusée) ; interopérabilité avec le binaire `age` quand il est présent (sinon test sauté, CI qui l'installe) ; construction du manifeste sur une arborescence dans `tmp_path` ; rétention quotidienne, hebdomadaire et mensuelle ; planification avec décalage et changement d'heure ; diff d'une zone et découpage en UPDATE ; plan de restauration (parties, permissions, refus de types) ; destinations locale et SFTP avec un faux `sftp` ; API.
- Démons : named et Kea réels ; archive pendant que des UPDATE arrivent (serial cohérent dans l'instantané) ; restauration d'une zone par diff et par remplacement ; restauration de la configuration Kea avec `config-test` ; échange entre deux nœuds (`/repl/v1/archives`).
- Labo : `tests/lab/test_archives_lab.py` : destination SFTP (conteneur sur la VM Docker du labo) et pair ; destruction du nœud ns2 (retour à l'instantané `clean`), installation du paquet, `pelagos restore` depuis l'archive gardée par ns1, retour dans le cluster, convergence, HA Kea et transferts de zone vérifiés ; puis le mode 2 (nœud neuf enrôlé, moteurs restaurés).

### 13.3 DDNS sans point unique de panne (point 58)

**Besoin**

D2 n'envoie qu'au primaire DNS : si le serveur qui porte le primaire tombe, la HA Kea continue de distribuer des baux mais plus aucun nom n'est créé ni retiré, et rien n'est rattrapé à son retour. L'alerte `ddns_advice` (sujet `d2:dns-servers`, `collector/checks/ddns.py`) le signale déjà ; il manque la solution.

**Faits vérifiés** (sources consultées le 2026-10-28)

- D2 essaie les serveurs d'un domaine du premier au dernier et passe au suivant quand l'essai échoue, jusqu'à réussir ou épuiser la liste ([Kea 2.6.3 ARM, DHCP-DDNS](https://kea.readthedocs.io/en/kea-2.6.3/arm/ddns.html)). Il passe au suivant sur erreur de communication (`DHCP_DDNS_FORWARD_ADD_IO_ERROR` : « will retry against the same server or others »), pas sur un refus : un RCODE comme REFUSED termine la requête (`DHCP_DDNS_FORWARD_ADD_REJECTED`, [messages Kea 2.6.3](https://kea.readthedocs.io/en/kea-2.6.3/kea-messages.html)). Conséquence : un serveur qui refuse ne doit jamais être devant celui qui accepte.
- D2 ne garde pas ses requêtes : la file est perdue à l'arrêt (même page, « DHCP-DDNS Server Limitations »), et une requête qui a épuisé la liste n'est pas rejouée.
- `lease4-resend-ddns` et `lease6-resend-ddns` (hook `lease_cmds`, présent en 2.6.3) régénèrent la requête DNS d'un bail existant, si le DDNS est actif, que le bail a un nom et un drapeau `fqdn_fwd` ou `fqdn_rev` ([Kea 2.6.3 ARM, Lease Commands](https://kea.readthedocs.io/en/kea-2.6.3/arm/hooks.html)). C'est l'outil de rattrapage : Kea reste la vérité des baux.
- `allow-update-forwarding` sur un secondaire transmet l'UPDATE au primaire ([ARM BIND 9.20](https://bind9.readthedocs.io/en/v9.20.0/reference.html)) : si le primaire est arrêté, la transmission échoue aussi. Cette option ne supprime donc pas le point unique de panne ; elle n'est pas retenue.
- Les zones secondaires sont écrites par défaut au format `raw` (`masterfile-format`, même ARM) : une copie promue doit être réécrite en texte ou déclarée `masterfile-format raw`.

**Décisions**

1. Pas de multi-primaire. BIND n'a pas de réplication entre primaires : deux primaires d'une même zone divergent (serials, DHCID) sans moyen de fusion. Le document le dit, et Pelagos refuse cette configuration.
2. Un primaire actif par zone, un secondaire prêt à être promu, et une bascule de rôle par plan. L'état « qui est primaire de quelle zone, à quelle époque » vit dans `cluster.toml` (`ddns.roles`, une entrée par `<vue>/<zone>` : `primary`, `epoch`, `since`, `by`), répliqué.
3. Préparation, quand tout va bien (plan « Préparer la reprise du DDNS ») :
   - prérequis : la zone est déclarée dans les fichiers gérés par Pelagos sur chaque nœud (sinon l'écran propose d'abord « Confier la zone à Pelagos », point 33, déjà livré), elle n'est pas signée par une `dnssec-policy` (limite de la première version : les clés ne sont que sur le primaire), elle est dans la vue par défaut ou dans une vue que la clé `kea-ddns` sélectionne ;
   - les clés `kea-ddns` et `ddi-admin` déclarées sur chaque secondaire (sans effet tant qu'il est secondaire) ;
   - dans la configuration de chaque D2, `dns-servers` de chaque domaine = primaire d'abord, puis chaque secondaire ;
   - l'entrée `ddns.roles` de la zone, avec la politique `update-policy` et les options à remettre en cas de promotion.
   Tant que le primaire répond, rien ne change pour les clients. S'il ne répond plus, D2 essaie le secondaire, qui refuse (REFUSED) : la requête échoue, mais l'erreur est visible et comptée par D2.
4. Bascule (plan « Promouvoir ns2 primaire de example.lan », proposé par l'alerte `ddns_outage`) : sur le secondaire, la copie est relue par AXFR locale et écrite en texte dans le dossier des zones de Pelagos, la zone redéclarée `type primary` avec sa politique, `rndc reconfig` ; sur chaque D2 joignable, l'ordre de `dns-servers` est inversé (nouveau primaire d'abord) ; `ddns.roles` passe à l'époque suivante. Puis le plan de rattrapage est proposé. Le plan refuse de promouvoir si l'ancien primaire répond encore (c'est alors un changement planifié, ci-dessous).
5. Retour de l'ancien primaire, sans double primaire : au démarrage, après la synchronisation de la réplication, le collecteur compare les zones primaires qu'il sert à `ddns.roles`. Une zone dont le rôle a été donné à un autre nœud à une époque plus récente est rétrogradée automatiquement (`demote_on_return_enabled`, défaut vrai) : déclaration `type secondary` du nouveau primaire, fichier et journal déplacés dans la sauvegarde du pipeline avant le `rndc reconfig`, de sorte que la copie n'a plus de serial local et reprend la zone du nouveau primaire par transfert complet (`rndc retransfer` à la suite), entrée d'audit `system`. Entre le démarrage de named et ce contrôle, l'ancien primaire est deuxième dans les listes de D2 et ne reçoit donc rien tant que le nouveau répond ; une mise à jour qu'il aurait acceptée dans cet intervalle est perdue à la rétrogradation et reprise par le rattrapage. L'alerte `dns_stale_primary` (critical) reste levée tant que la rétrogradation n'est pas faite.
6. Changement planifié (plan « Rendre le rôle à ns1 », les deux nœuds en ligne) : `rndc freeze` de la zone sur le primaire actuel (les UPDATE sont refusés pendant quelques secondes), attente que la copie de la cible ait le même serial, promotion de la cible, rétrogradation de l'autre, inversion des listes de D2, `ddns.roles` à l'époque suivante, puis rattrapage des baux de la fenêtre.
7. Rattrapage (plan « Rejouer le DDNS ») : fenêtre = début et fin de la panne (premier `update-timeout` ou `peer_offline` du primaire, jusqu'à la bascule ou au retour). Pelagos liste les baux actifs dont `cltt` tombe dans la fenêtre, qui ont un nom et un drapeau fqdn, et dont l'A, l'AAAA ou le PTR manque ou diffère (même jointure que les incohérences `lease_without_record`) ; le plan envoie `lease4-resend-ddns` / `lease6-resend-ddns` pour chacun sur un nœud dont Kea sert, par lots. Les noms dont le bail a disparu pendant la panne sont déjà levés par `record_without_lease` et les PTR orphelins, avec leurs plans existants. Un renvoi sur un nom déjà juste est sans effet (résolution de conflit par DHCID). Sans panne connue (aucun échec compté par D2), aucune mise à jour n'est réputée perdue : l'écran n'affiche ni fenêtre par défaut ni décompte, et propose une « fenêtre manuelle » dont l'opérateur saisit le début ; un bail sans enregistrement hors panne relève de `lease_without_record`.
8. Automatisme : la bascule reste manuelle par défaut, avec notification (13.1) dès que l'alerte s'ouvre ; `failover_auto_enabled` permet de la faire seule après `failover_after_seconds` d'indisponibilité vue par tous les autres nœuds. Le rattrapage passe toujours par un plan confirmé (décision 6), borné par `replay_max_leases`.

**Écrans**

- DHCP, DDNS, nouvel onglet « Reprise » : par zone dynamique, le primaire actif, l'époque, les copies, l'état (prête, non préparée avec la raison, en panne depuis, ancien primaire à rétrograder) ; par D2, la liste ordonnée des serveurs de chaque domaine avec le rôle de chacun. Actions : Préparer, Promouvoir, Rendre le rôle, Rejouer (nombre de baux concernés et fenêtre affichés avant le plan).
- Fiche de zone : badge « primaire actif sur ns2 depuis ... (époque 3) ».
- Tableau de bord : tuile DDNS avec l'état de reprise.
- Chaque action ouvre l'aperçu de plan habituel (diff de chaque nœud, `named-checkconf`, `config-test` de D2, confirmation).

**API**

| Méthode, chemin | Permission | Requête | Réponse |
| --- | --- | --- | --- |
| `GET /dhcp/ddns/resilience` | `read:dhcp` et `read:dns` | | `{"zones": [{"zone","view","primary_node_id","epoch","since","copies","ready","blockers": [message]}], "d2": [{"node_id","domains": [{"direction","name","servers": [{"address","node_id","role"}]}]}], "outage": {"since","zones"}|null, "replay": {"from","to","candidates"}}` |
| `POST /dhcp/ddns/resilience/plan` | `write:dns.zones`, `write:dhcp.config` | `{"zones"?}` (défaut : toutes les zones dynamiques) | `Plan` composite (clés sur les secondaires, listes de D2, `ddns.roles`) |
| `POST /dhcp/ddns/failover/plan` | `write:dns.zones`, `write:dhcp.config` | `{"to_node_id","zones"?}` | `Plan` (`requires_confirmation` ; `409` si l'ancien primaire répond) |
| `POST /dhcp/ddns/switchover/plan` | `write:dns.zones`, `write:dhcp.config` | `{"to_node_id","zones"?}` | `Plan` (`requires_confirmation`) |
| `POST /dhcp/ddns/replay/plan` | `ops:dhcp.leases` | `{"from"?,"to"?,"family"?,"limit"?}` | `Plan` (une modification par bail, cible `dhcp.lease` `resend/<ip>`) |

Les opérations `lease4-resend-ddns` et `lease6-resend-ddns` entrent aussi dans la liste autorisée de `/dhcp/{family}/ops` (permission `ops:dhcp.leases`). Les plans de bascule sont des composites (`PlanService.register_composite`) dont les parties sont des plans BIND (`dns.zone`, `dns.config`) et D2 (`d2.config`) déjà connus ; le nouveau scope `dns.failover` ne sert qu'à la ligne d'audit de synthèse. Une partie destinée à un pair est construite chez lui par l'action de pair `dns.zone.plan` existante.

**Réglages**

`[settings.ddns]` : `failover_auto_enabled` (faux), `failover_after_seconds` (300), `demote_on_return_enabled` (vrai), `replay_max_leases` (2000), `replay_window_max_hours` (72). Écrit par l'écran : `ddns.roles`. Pas de secret nouveau : les clés existent déjà.

Alertes : `ddns_outage` (critical ; sujet `ddns:<vue>/<zone>` ; le primaire actif ne reçoit plus de mises à jour : D2 en `update-timeout`, nœud hors ligne ou named arrêté ; propose la promotion), `ddns_replay` (warning ; sujet `ddns:replay` ; des baux de la dernière panne n'ont pas leurs enregistrements ; propose le rattrapage), `dns_stale_primary` (critical ; sujet `ddns:stale:<vue>/<zone>` ; un nœud sert en primaire une zone que `ddns.roles` donne à un autre). `ddns_advice` (`d2:dns-servers`) propose désormais le plan de préparation.

**Plusieurs nœuds**

Avec trois nœuds ou plus, chaque secondaire est dans les listes de D2 et peut être promu ; le plan de promotion choisit la cible (défaut : la copie au serial le plus haut). Les autres secondaires sont repointés vers le nouveau primaire (`primaries`) dans le même plan. Les D2 injoignables pendant la bascule (celui du nœud tombé) sont corrigés à leur retour par le même contrôle que la rétrogradation (liste de D2 différente de `ddns.roles` : plan proposé, ou appliqué seul si `demote_on_return_enabled`).

**Sécurité**

- Aucune clé nouvelle ni élargie : `kea-ddns` garde exactement ses types sur la zone promue (la politique est recopiée, pas reconstruite) ; `ddi-admin` de même.
- Pas d'`allow-update-forwarding`, pas de mise à jour par adresse IP.
- La rétrogradation automatique ne touche que les zones listées dans `ddns.roles`, jamais une zone de l'utilisateur non préparée.
- Promotion, retour et rattrapage sont audités, avec l'époque.

**Pannes**

| Panne | Comportement |
| --- | --- |
| Primaire arrêté, rien de préparé | `ddns_advice` puis `ddns_outage` ; seule action possible : rattrapage au retour |
| Primaire arrêté, préparé | `ddns_outage`, notification, promotion (manuelle ou automatique), rattrapage |
| Ancien primaire revenu | Rétrogradation automatique, `retransfer`, rattrapage de l'intervalle |
| Coupure réseau entre nœuds (les deux vivants) | Pas de promotion automatique tant qu'un nœud voit encore le primaire ; manuelle seulement avec confirmation qui rappelle le risque |
| Copie du secondaire en retard | Le plan affiche l'écart de serial ; les noms perdus reviennent par le rattrapage |
| D2 d'un nœud injoignable pendant la bascule | Corrigé à son retour (ci-dessus) |
| Zone signée | Préparation refusée avec la raison (limite de la première version) |
| `lease_cmds` non chargé | Rattrapage indisponible, dit dans l'écran, proposition de charger le hook (plan existant) |

**Tests**

- Unitaires : contrôle de préparation (zone non gérée, signée, vue) ; construction des plans de préparation, de promotion (réécriture en texte, politique recopiée, listes de D2 inversées) et de retour ; décision de rétrogradation à partir de `ddns.roles` et des époques ; fenêtre de panne depuis les statistiques de D2 et les états des pairs ; sélection des baux à rejouer ; alertes nouvelles ; API.
- Démons : deux named réels (primaire et secondaire sur des ports libres), un D2 et un `kea-dhcp4` réels avec `lease_cmds` : préparation ; arrêt du primaire, D2 passe au secondaire (compteurs) ; promotion ; mise à jour acceptée par le nouveau primaire ; redémarrage de l'ancien, rétrogradation, serials égaux ; `lease4-add` d'un bail nommé puis `lease4-resend-ddns`, enregistrement créé.
- Labo : `tests/lab/test_ddns_failover_lab.py` sur la paire Kea 2.6.3 Debian (ns1, ns2 et le client DHCP du labo) : préparation ; arrêt de la VM du primaire par l'API Proxmox ; bail obtenu par le client, promotion, A et PTR créés sur le nouveau primaire ; retour de la VM, rétrogradation, rattrapage ; changement planifié pour rendre le rôle ; aucune entrée perdue de bout en bout.

### 13.4 Migration de Kea 2.6 vers 3.x (point 59)

**Besoin**

La production tourne sur Kea 2.6.3 de Debian 13, en HA hot-standby, avec D2. ISC ne maintient plus la série 2.6 depuis la sortie de 3.2.0 (« With the release of Kea 3.2.0 we obsoleted Kea 2.6 », [kea-announce, juillet 2026](https://lists.isc.org/pipermail/kea-announce/2026-July.txt), lu le 2026-10-28) ; seule la sécurité de Debian suit encore le paquet `2.6.3-1+deb13u1`. Passer en 3.x à la main est risqué : HA incompatible entre les deux séries, paquets qui se remplacent, chemins restreints, clés renommées, agent de contrôle retiré. Pelagos doit analyser la configuration, dire ce qui casse, produire la configuration 3.x, faire la bascule nœud par nœud avec la coupure DHCP la plus courte possible, et savoir revenir en 2.6.

**Ce qui existe et sur quoi on s'appuie**

- Les connecteurs parlent aux deux séries : `connectors/kea/config.py` (`is_v3`, `normalize_root`, renommage `require-client-classes` / `evaluate-additional-classes` et `only-if-required` / `only-in-additional-list`, refus des clés 3.x vers un 2.6), `schema.py` (descriptions `kea-2.6.json` et `kea-3.json`), et la version est relue après un redémarrage (`backend.py`, « an in-place upgrade (2.6 to 3.x) changes the key names to write »).
- L'installateur sait poser le dépôt ISC Cloudsmith d'une série (`platform/packages.py`, `isc_repo_files`, série par défaut `3.2`), installer les paquets ISC à la place de ceux de la distribution (`step_packages`, `replace=True`), désactiver les profils AppArmor laissés par les paquets Debian retirés (`disable_stale_apparmor`), poser la socket de contrôle sous la bonne forme (`keasetup.socket_key_for`, `control-sockets` dès 2.7.2) et passer les secrets TSIG de D2 en `secret-file` (`migrate_inline_secrets`).
- La HA : fenêtres de maintenance (`core/ha_maintenance.py`, `ha-maintenance-start` / `cancel`), lecture des écouteurs HA et de `restrict-commands` (`installer/ha_listener.py`), TLS de la HA par la CA du cluster (`core/kea_ha_tls.py`, point 54).
- Les sauvegardes (13.2) donnent une archive juste avant la migration ; le pipeline d'écriture garde la configuration d'avant chaque écriture.

**Faits vérifiés** (sources lues le 2026-10-28)

- HA : « All Kea HA partners must run Kea 2.7.0 or later », et le listener HA ne prend plus que les commandes de la HA ([KB ISC, Things to be aware of when upgrading to Kea 3.0.0](https://kb.isc.org/docs/things-to-be-aware-of-when-upgrading-to-kea-300)). Une paire mixte 2.6 / 3.x n'est donc pas prise en charge : pas de paire temporaire, une fenêtre courte est nécessaire. L'ARM documente la mise à niveau « un serveur après l'autre » à l'intérieur d'une même série compatible ([ARM Kea 3.2.1, hooks-ha.rst, Controlled Shutdown and Maintenance](https://gitlab.isc.org/isc-projects/kea/-/blob/Kea-3.2.1/doc/sphinx/arm/hooks-ha.rst)).
- `restrict-commands` : la KB 3.0 dit qu'il vaut `true` par défaut depuis 3.0, la KB 3.2 dit que le défaut passe de `false` (3.0) à `true` (3.2) ([KB ISC, Kea 3.2](https://kb.isc.org/docs/things-to-be-aware-of-when-upgrading-to-kea-3-2)). Les deux se contredisent : la configuration générée l'écrit toujours explicitement à `true`.
- Agent de contrôle : déprécié en 3.0, « no longer included in the Kea distribution » à partir de 3.2 (même article ; [KB ISC, Kea Control Agent migration](https://kb.isc.org/docs/kea-control-agent-migration) : « deprecated in Kea 3.0, and has been removed as of Kea 3.2 »). Le paquet `isc-kea-ctrl-agent` 3.2.1 de Cloudsmith n'est plus qu'un « transitional package, can be safely removed ». Chaque démon prend ses commandes par `control-sockets` (types `unix`, `http`, `https`), un port TCP par démon pour l'accès HTTP. Pelagos n'utilise que les sockets Unix : rien ne change pour lui.
- Chemins restreints en 3.x : hooks seulement depuis le dossier des hooks, sockets dans un dossier 0750, baux et DUID dans le dossier de données, journaux dans le dossier des journaux, scripts de `run_script` dans `share/kea/scripts/` ; `-X` lève les restrictions avec un avertissement ; `-T` valide une configuration avant la mise à niveau, `-W` donne les dossiers compilés (KB 3.0).
- Paramètres : `require-client-classes` devient `evaluate-additional-classes`, `only-if-required` devient `only-in-additional-list`, `client-class` cède la place à `client-classes` (pas les deux dans une même portée) ; les classes additionnelles sans test sont toujours ajoutées, sont évaluées dans l'ordre de `option-data`, et la priorité des options des classes modèles est inversée (KB 3.0). Le cache des baux est actif par défaut. MySQL et PostgreSQL passent dans des hooks (`libdhcp_mysql.so`, `libdhcp_pgsql.so`, paquets `isc-kea-mysql`, `isc-kea-pgsql`) ; les hooks RBAC et CB restent commerciaux. « There have been no incompatible changes to the lease file format » (KB 3.0) : le retour en 2.6 garde les baux memfile.
- Kea 3.2 : les paquets ISC redémarrent les services Kea pendant une mise à niveau et systemd relance un démon qui sort en échec ; les exécutables sont `_kea:_kea` en 0750 (KB 3.2). Les clés TSIG de D2 exigent `secret-file` (règle des fixtures d'AGENTS.md, vérifiée sur 3.2.1).
- Paquets pour Debian 13 (relevé le 2026-10-28) : dépôt ISC [`kea-3-2`](https://dl.cloudsmith.io/public/isc/kea-3-2/deb/debian/dists/trixie/Release), version 3.2.1-isc20260928103142, et `kea-3-0`, version 3.0.5-isc20261026134027, tous deux en amd64 et arm64 (paquets `isc-kea-dhcp4`, `isc-kea-dhcp6`, `isc-kea-dhcp-ddns`, `isc-kea-hooks`, `isc-kea-common`, `isc-kea-admin`). Debian : `kea-dhcp4-server` 2.6.3-1+deb13u1 dans trixie, 3.0.3-1~bpo13+1 dans trixie-backports, 3.0.4-2 dans forky et sid, amd64 et arm64 ([madison](https://qa.debian.org/madison.php?package=kea-dhcp4-server&text=on&a=arm64,amd64)). Les backports sont fournis « on an as-is basis », sans engagement de l'équipe de sécurité ([backports.debian.org](https://backports.debian.org/)). Le paquet ISC `isc-kea-dhcp4` déclare `Conflicts: kea-dhcp4-server` : l'un remplace l'autre.
- Dossier des hooks des paquets ISC sur Debian : `/usr/lib/<multiarch>/kea/hooks` (relu par `kea-dhcp4 -W` sur 3.2.1), le même que celui des paquets Debian : les chemins `library` restent valides. Debian 2.6.3 livre `bootp`, `flex_option`, `ha`, `lease_cmds`, `mysql_cb`, `pgsql_cb`, `perfmon`, `run_script`, `stat_cmds` (contenu des paquets `kea-common` et `kea-dhcp4-server`) ; ISC 3.2.1 y ajoute notamment `host_cmds`, `subnet_cmds`, `class_cmds`, `lease_query`, `ping_check`, mais plus `mysql_cb` ni `pgsql_cb` (CB commercial).

**Vérifié au labo par le lot K1** (2026-10-29, Debian 13 avec Kea 2.6.3 de Debian, HA hot-standby en TLS avec `require-client-certs`, D2 avec `secret` en clair, `kea-ctrl-agent` installé ; Rocky 10 pour `dnf`)

- La validation à blanc est fiable et retenue : paquets ISC 3.2.1, ISC 3.0.5 et backports 3.0.3 téléchargés avec une liste de sources, une clé et un cache privés (rien n'est écrit dans `/etc/apt`), extraits par `dpkg-deb -x` (`rpm2cpio` sur Rocky), démons lancés depuis l'arbre extrait avec `LD_LIBRARY_PATH` et `KEA_HOOKS_PATH`, sous l'utilisateur Kea. Les bibliothèques 3.x ont d'autres SONAME que celles de 2.6 et leurs dépendances (libc, log4cplus, OpenSSL, libstdc++) sont celles qu'un nœud Kea a déjà. Un démon qui ne démarre pas (bibliothèque absente, vu sur un Rocky sans Kea) ou un téléchargement en échec donne `validation_skipped` : le repli de la décision 3 (validation sur le premier nœud migré) ne sert qu'à ce cas. Preuve rejouable : `backend/tests/lab/test_kea_migration_lab.py` (lab-ns1 pour ISC 3.2 et backports 3.0, lab-rpm pour `dnf`, état d'apt, de dnf et des clés comparé avant et après). Avec dnf 4, les greffons sont coupés sauf `download` : `generate_completion_cache` écrivait les paquets ISC dans `/var/cache/dnf/packages.db`.
- `-T` et non `-t` pour `kea-dhcp4` et `kea-dhcp6` : `-T` charge les hooks et lit leurs fichiers (une clé TLS de la HA absente ou illisible par `_kea` est refusée) ; D2 n'a que `-t`. Ni `-t` ni `-T` ne contrôlent les chemins des baux et des journaux (seulement au démarrage) : les règles de l'analyse les couvrent.
- Avec `KEA_HOOKS_PATH`, un `library` absolu hors de ce dossier est refusé (« invalid path specified ») : la copie validée nomme les hooks sans dossier.
- Socket de contrôle : le Kea d'ISC n'accepte que `/var/run/kea` et celui des backports Debian que `/run/kea` (comparaison de chaînes, « supported path is ») ; la configuration produite porte un nom de socket nu, valable pour les deux.
- Kea 3.2.1 accepte encore `require-client-classes` et `client-class` avec un avertissement (`DHCPSRV_REQUIRE_CLIENT_CLASSES_DEPRECATED`, `DHCPSRV_CLIENT_CLASS_DEPRECATED`), refuse `client-class` et `client-classes` ensemble, refuse le `secret` TSIG en clair (« use of clear text TSIG 'secret' is NOT SECURE ») et exige que le `secret-file` existe.
- `restrict-commands` : l'ARM 3.2.1 (`hooks-ha.rst`) tranche, « The default is true since Kea 3.0.0 ». Le défaut de `sanity-checks.lease-checks` reste `warn` en 2.6.3 comme en 3.2.1 : le constat `lease_checks` est une information. Le cache des baux est actif depuis 3.0.0 (ChangeLog 2360, `cache-threshold` 0,25).
- Une HA sans écouteur dédié (`http-dedicated-listener` ou `enable-multi-threading` à false dans la relation, ou multi-thread du serveur coupé) passe par `kea-ctrl-agent` en 2.6 (ARM 2.6.3, `hooks-ha.rst`, « the server relies on kea-ctrl-agent ») : constat `ha_no_listener`, bloquant vers 3.2, comportement vers 3.0.
- `kea-ctrl-agent` actif sans client vu au moment de l'analyse : pas d'arrêt, un client périodique (Stork, cron, supervision) n'est pas connecté en permanence. Sont des clients : une connexion établie sur son port, une commande dans ses journaux (`CTRL_AGENT_COMMAND_RECEIVED`, niveau INFO, adresse distante, 30 jours de journal et ses fichiers de journal), un agent Stork actif ; sont des indices : écoute hors bouclage, authentification, TLS. Sans client, le constat `ctrl_agent_unverified` laisse la décision à l'administrateur ; seul un agent présent mais arrêté donne `ctrl_agent_stop`.

**Vérifié au labo par le lot K5** (2026-10-30, paire lab-k1a / lab-k1b du lot K1, client DHCP qui renouvelle toutes les 3 s et une requête INIT-REBOOT par seconde, capture tcpdump)

- Migration vers ISC 3.2.1 : coupure mesurée par Pelagos 14,6 s (arrêt de P jusqu'à `partner-down` de S et une page de baux qui répond) pour un `max-response-delay` de 10 s ; plus long trou vu par le client 14,0 s ; aucun DHCPNAK ; le client garde son adresse ; un bail donné par P seul pendant le temps 1 est présent sur les deux nœuds après ; DDNS fonctionne ensuite. Migration complète en 72 s.
- Retour automatique : seuil de 30 s contre une détection de 60 s, retour en 2.6 seul (fichiers, paquets et services comme avant), trou client de 55 s, aucun DHCPNAK.
- Retour de la paire migrée en 2.6 avec la même fenêtre : coupure 13,8 s, aucun DHCPNAK, fichiers et paquets comme avant la migration.
- `kea-lfc` compacte le fichier de baux et ses restes `.2` / `.1` concaténés ; le résultat est dans son fichier `-x` (essai sur 3.2.1). Pelagos le lance sur une copie, jamais sur les fichiers du nœud.

**Vérifié au labo par le lot K7** (2026-10-30, campagne de bout en bout rejouable, `scripts/lab/README.md`)

- Paire Debian (`test_kea_migration_e2e_lab.py`, depuis l'instantané `k1-ha26`, 8 min 25) : analyse sans constat bloquant, TLS de la HA gardé, secret D2 converti ; retour automatique au temps 2 (trou client 60 s, aucun DHCPNAK) ; migration vers ISC 3.2.1 en 70 s, coupure mesurée 16,2 s, trou client 16,0 s, aucun DHCPNAK, aucune adresse donnée à deux clients, baux identiques sur les deux nœuds, écouteur HA de chaque nœud qui refuse un pair sans certificat de la CA ; retour de la paire en 66 s, coupure 14,9 s, aucun DHCPNAK, fichiers et paquets comme avant.
- Rocky 10 (`test_kea_migration_rocky_lab.py`, nœud seul, SELinux actif) : ISC Kea 2.6.5 du dépôt `kea-2-6` (el/10) vers ISC 3.2.1 par dnf, coupure 7 s, aucun DHCPNAK, bail gardé, DDNS par le `secret-file` converti, aucun refus SELinux ; retour en 2.6.5 avec fichiers, étiquettes SELinux et paquets comme avant. Rocky 10 livre lui-même Kea 3.0.3 (`kea`, BaseOS) : la seule source 2.6 sur Rocky 10 est celle d'ISC.

**Décisions**

1. Cible par défaut : Kea 3.2 des dépôts ISC (Cloudsmith `kea-3-2`), la série que Pelagos teste déjà sur l'hôte de développement et que l'installateur pose par défaut. Les backports Debian (3.0) sont proposés comme seconde source, avec l'avertissement sur leur suivi de sécurité ; la série 3.0 d'ISC reste possible. Une seule série pour tout le cluster.
2. Pas de paire HA mixte : la bascule est une fenêtre courte et contrôlée, sans dépendre d'une compatibilité que la KB exclut. Si les essais du labo montrent qu'un 3.x se synchronise quand même avec un 2.6, ce n'est pas utilisé.
3. Analyse d'abord, sans rien changer (« Analyser la migration ») : lecture du fichier de configuration de chaque démon de chaque nœud, tel que Kea le lit (un écart avec la configuration en cours reste le travail de l'alerte `config_divergence`), puis un rapport de constats classés `bloquant`, `converti` (Pelagos le fait), `changement de comportement` (à lire), `info`. Règles :
   - clés renommées ou remplacées (ci-dessus), `client-class` et `client-classes` dans une même portée, sous-réseau sans `subnet-id` ;
   - hooks : chaque `library` doit exister sous le même nom dans le dossier des hooks de la cible ; `libdhcp_mysql_cb.so` ou `libdhcp_pgsql_cb.so` (CB, commercial) est bloquant ; une base de baux ou d'hôtes MySQL ou PostgreSQL ajoute le hook et le paquet `isc-kea-mysql` / `isc-kea-pgsql` ;
   - chemins hors des dossiers autorisés (journaux, baux, sockets, scripts) : déplacés vers les dossiers de la cible quand c'est un fichier de Kea, bloquant pour un script de `run_script` hors de `share/kea/scripts/` ;
   - `kea-ctrl-agent` actif : sa configuration et ses journaux sont lus ; arrêté, il est désactivé ; actif sans client prouvé, l'administrateur tranche (un client périodique n'est pas exclu) ; si un client HTTP externe l'utilise (Stork, scripts), le rapport le signale (`ctrl_agent_clients`, comportement) : la 0.3.0 ne crée pas les `control-sockets` `https` par démon (certificat de la CA du cluster, `cert-required`), l'administrateur les ajoute après la migration ; l'option `https_sockets` est refusée tant qu'elle n'est pas construite (relecture globale de la passe 8, 2026-10-30) ;
   - HA : `restrict-commands` écrit à `true`, TLS de la HA conservé tel quel (mêmes clés en 3.x), contrôle que la configuration des deux pairs reste symétrique ;
   - D2 : `secret` en clair converti en `secret-file`, `control-socket` converti en `control-sockets` ;
   - classes additionnelles sans test, classes modèles avec options, absence de `lease-checks` explicites, cache des baux : `changement de comportement` ;
   - la configuration produite passe `kea-dhcp4 -T` / `kea-dhcp6 -T` / `kea-dhcp-ddns -t` avec les binaires 3.x. Avant toute installation, ces binaires sont extraits des paquets téléchargés dans un dossier temporaire (`apt-get download`, `dpkg-deb -x`, `KEA_HOOKS_PATH` vers les hooks extraits) ; si cette validation à blanc n'est pas fiable (à prouver par le lot K1), la validation se fait sur le premier nœud migré, avant la fenêtre de coupure.
4. Préparation (plan « Préparer la migration », sans coupure) : archive (13.2) de chaque nœud, téléchargement des paquets sur chaque nœud (`apt-get install --download-only`, `dnf download`) pour que la fenêtre ne dépende pas du réseau, configurations 3.x écrites à côté (`/var/lib/pelagos/kea-migration/<id>/`, jamais dans `/etc/kea` avant la bascule), sauvegarde des configurations 2.6 et de la liste des paquets installés avec leurs versions exactes.
5. Bascule d'une paire hot-standby, primaire P, standby S, en trois temps (plan composite « Migrer vers Kea 3.2 », une étape par ligne du job, arrêt au premier échec) :
   1. S d'abord, sans coupure : `ha-maintenance-start` envoyé à P (P sert seul) ; arrêt de Kea sur S ; installation des paquets ISC (qui retirent ceux de Debian) ; dépôt des configurations 3.x ; `kea-dhcp4 -t` réel ; S reste arrêté. Avant tout cela, la configuration 3.x de P est validée sur P lui-même, par les binaires cibles extraits de ses paquets préparés, exactement comme l'analyse et la préparation l'ont fait (0.3.1, point 82 : en 0.3.0, S validait le fichier de P et refusait son `interfaces-config` et l'`interface` de son sous-réseau, des noms propres à P ; un fichier ne quitte plus son hôte, et une paire acceptée par la préparation n'est plus refusée au temps 1).
   2. La fenêtre : arrêt de Kea sur P (la coupure DHCP commence) ; P fait son LFC, son fichier de baux est copié vers S par le canal de réplication (mTLS, somme vérifiée) et remplace celui de S, qui n'a pas vu les baux donnés pendant le temps 1 ; démarrage de S en 3.x ; S ne joint pas son partenaire et passe `partner-down` après la détection de panne. Pour raccourcir cette détection, la configuration 3.x de S porte pendant la migration un `max-response-delay` réduit (`migration_response_delay_ms`, défaut 10 000) et `max-unacked-clients: 0`, remis à leur valeur au temps 3. Fin de la coupure quand `status-get` de S dit `partner-down` et qu'un `lease4-get-all` répond. Durée visée : moins d'une minute, mesurée et affichée.
   3. P ensuite, sans coupure : installation des paquets sur P, configuration 3.x, démarrage ; P se synchronise sur S par la HA normale (3.x des deux côtés) et la paire revient en `hot-standby` avec P qui sert ; remise des délais de détection d'origine (le fichier tel qu'il était, puis `config-reload` : un `config-write` réécrirait le fichier de l'administrateur avec toutes les valeurs par défaut) ; D2 démarré en 3.x sur chaque nœud dans le temps du nœud.
   En `load-balancing`, même suite (le pair qui reste sert tout pendant le temps 1). Un nœud sans HA est migré seul, avec une coupure égale au redémarrage. Un serveur `backup` passe avant S.
6. Retour arrière, par nœud et pour la paire :
   - pendant le temps 1 ou 2 : S remis en 2.6 (paquets Debian aux versions notées, configurations d'avant, profils AppArmor réactivés), redémarré, `ha-maintenance-cancel` sur P ; le fichier de baux de S n'a pas changé de format ;
   - après le temps 3 : retour de la paire entière (une paire mixte n'existe pas) par la même chorégraphie à l'envers, avec la même fenêtre courte ; proposé seulement tant que l'archive de préparation et les paquets 2.6 sont présents ;
   - automatique si une étape de vérification échoue pendant les temps 1 et 2 (`auto_rollback_enabled`, défaut vrai), toujours manuel après la fin du temps 3.
   - Robustesse du retour (0.3.1, point 82, constaté en production le 2026-10-30) : les paquets 2.6 conservés sont installés par leur chemin, sommes vérifiées, avec leur dossier comme cache d'apt (un `.deb` local dont la version figure aussi dans l'index Debian était sinon recherché sur le miroir, et `--no-download` répondait « Unable to fetch some archives ») ; chaque partie du retour d'un nœud (paquets, fichiers de `/etc/kea`, dossiers, liens AppArmor `disable/`, fichiers de dépôt, état activé des unités, paquets ISC `rc` purgés sans leurs scripts de purge qui effaceraient `/etc/kea` et l'utilisateur `_kea`) s'exécute même si une autre échoue, et toutes les erreurs sont rapportées ; un fichier ajouté que la préparation n'avait pas vu est mis de côté, jamais effacé ; sans AppArmor actif (pas de securityfs), seul le lien est retiré. Avant le temps 3, un nœud qui ne revient pas n'empêche jamais P de redémarrer : ses étapes suivantes et celles de la paire sont sautées et signalées, celles de P s'exécutent. Le retour finit par une vérification de la HA depuis P et depuis S.
   - Reprise d'un état incohérent (0.3.1) : action « Constater l'état réel, marquer comme revenu en 2.6 » (phase `reconcile`, mêmes droits que la migration, plan avec confirmation, entrée d'audit `kea.migration.reconcile`) : chaque nœud relit ses paquets Kea (aucun paquet ISC installé, versions exactes notées à la préparation), fait valider son fichier par le démon installé, vérifie ses services, la HA est sondée ; si tout est sain sur la série précédente, la migration passe `rolled_back` sans toucher aux fichiers Kea, puis chaque nœud purge les paquets ISC `rc` et retire les dossiers de migration. Elle part de tout état sauf une phase en cours, y compris d'un enregistrement laissé par 0.3.0. Si un fichier de `/etc/kea` diffère de la copie de la préparation, cette copie (`private/before`) est gardée hors des dossiers de migration au lieu d'être effacée.
   - Versions (0.3.1, point 82) : aucune phase (préparation, migration, retour, constat) n'est planifiée tant qu'un nœud de la migration tourne en Pelagos antérieur à 0.3.1 ou ne donne pas sa version : le pilote envoie les étapes, mais chaque nœud les exécute avec son propre code, et celui de 0.3.0 est celui qui a échoué en production. Mettre d'abord chaque nœud en 0.3.1.
7. Après la migration : `config_divergence`, contrôles et écrans reprennent la série 3 sans action (version relue), les écritures par objet (`host_cmds`, `subnet_cmds`) deviennent disponibles et l'écran Hooks propose de les charger. Kea 2.6 reste lu et écrit en mode dégradé tant qu'un nœud du parc en a besoin (question 11 « Kea 2.6 en mode dégradé »).
8. Nouvelle alerte `kea_series_obsolete` (info, sujet `kea:series`) : un nœud fait tourner une série qu'ISC ne maintient plus ; elle propose l'analyse. La date de fin est une donnée du fichier des avis ISC empaqueté (`scripts/update-isc-advisories.py`), pas du code.

**Écrans**

- Installation, nouvel onglet « Migration Kea » : série de chaque nœud, source des paquets (distribution, ISC, backports), série cible et source choisies, bouton « Analyser ».
- Rapport : constats groupés par gravité, par nœud et par démon, chacun avec la ligne d'origine, ce que Pelagos fera et la référence ISC ; diff complet 2.6 vers 3.x par démon (même composant que les plans) ; liste des paquets qui seront retirés et installés ; durée de coupure estimée.
- Assistant en trois étapes (préparer, migrer, vérifier) qui montre la frise des temps 1 à 3 avec l'état HA de chaque nœud en direct (événements WebSocket `ha` existants), le temps de coupure mesuré, et un bouton « Revenir en 2.6 » tant que c'est possible.
- Bannière sur les pages DHCP quand `kea_series_obsolete` est ouverte.

**API**

| Méthode, chemin | Permission | Requête | Réponse |
| --- | --- | --- | --- |
| `GET /install/kea-migration` | `admin:install` | | `{"nodes": [{"node_id","engines": {"kea4": {"version","source","package"}}}], "targets": [{"series","source","version","available": bool}], "current": Migration|null}` |
| `POST /install/kea-migration/analyze` | `admin:install` | `{"series","source","node_ids"?}` | `{"id","findings": [{"severity","code","node_id","engine","path","message","action"}],"diffs": {node_id: {engine: diff}},"packages": {node_id: {"remove","install"}},"blocking": bool}` |
| `POST /install/kea-migration/{id}/plan` | `admin:install` et `ops:dhcp.ha` | `{"phase": "prepare"|"migrate"|"rollback","options"?: {"response_delay_milliseconds","auto_rollback"}}` | `Plan` composite (scope `kea.migration`, `requires_confirmation`) ; `409` si un constat bloquant reste ouvert |
| `GET /install/kea-migration/{id}` | `admin:install` | | `Migration` : `{"id","series","source","state","phase","nodes": [{"node_id","step","ha_state","started_at","finished_at"}],"outage_seconds","rollback_possible"}` |

Nouveau scope de plan `kea.migration`, permission `admin:install` plus `ops:dhcp.ha`. Audit : `kea.migration.analyze|prepare|step|rollback`. Les étapes qui touchent un pair passent par l'assistant privilégié du pair, scellées comme les étapes de la bascule TLS de la HA (`PEER_STEPS` de `installer/helper.py`).

**Réglages**

`[settings.kea]` : `migration_response_delay_milliseconds` (10 000), `migration_auto_rollback_enabled` (vrai), `migration_outage_max_seconds` (180 : au-delà, retour arrière automatique pendant le temps 2), `migration_lease_file_max_mb` (256 : taille maximale du fichier de baux copié). Pas de secret nouveau. Noms fixés par le contrat C5 (architecture, section 28) selon la règle de nommage des réglages ; l'option du plan s'appelle de même `response_delay_milliseconds`.

**Plusieurs nœuds**

Le plan est construit sur le nœud de l'administrateur ; chaque étape s'exécute sur son nœud par son assistant privilégié. Le fichier de baux passe par une nouvelle route de réplication `GET /repl/v1/kea/leases/<famille>` (mTLS, lecture seule, taille bornée). Le nœud qui pilote garde l'état de la migration dans `cluster.toml` (`kea.migration`), répliqué, pour qu'un autre nœud reprenne l'affichage ou le retour arrière si le pilote redémarre.

**Sécurité**

- Seuls les dépôts connus (ISC Cloudsmith, distribution) sont posés, avec leur clé de signature, comme l'installateur actuel. Les paquets téléchargés sont vérifiés par le gestionnaire de paquets (signature du dépôt), jamais installés depuis un chemin fourni par le client.
- La copie du fichier de baux ne quitte pas le canal mTLS et n'est jamais écrite hors du dossier de données de Kea et du dossier de migration (0700).
- Aucun `-X` en production. `restrict-commands: true` et TLS de la HA gardés ; `control-sockets` HTTP seulement sur demande, `https` avec `cert-required` par défaut.

**Pannes**

| Panne | Comportement |
| --- | --- |
| Paquet introuvable ou téléchargement en échec | Préparation en échec, rien n'est arrêté |
| `kea-dhcp4 -t` refuse la configuration 3.x | Temps 1 arrêté avant la fenêtre ; S remis en 2.6 ; constat ajouté au rapport |
| Noms d'interface différents d'un nœud à l'autre | Sans effet : chaque fichier est validé sur son propre nœud (analyse, préparation, temps 1) |
| Le retour automatique échoue sur S | P redémarre quand même, les étapes de la paire sont sautées, l'état `failed` liste chaque erreur ; retour manuel ou, après une remise en état à la main, « Constater l'état réel » |
| S ne passe pas `partner-down` dans `migration_outage_max_seconds` | Retour arrière automatique : arrêt de S, redémarrage de P en 2.6, `ha-maintenance-cancel` |
| P ne revient pas en `hot-standby` au temps 3 | S continue de servir seul (`partner-down`) ; `ha_partner_down` levée, pas de coupure ; correction manuelle ou retour de la paire |
| Nœud injoignable pendant la migration | Arrêt à l'étape en cours, état gardé dans `kea.migration`, reprise ou retour depuis l'autre nœud |
| AppArmor confine les binaires ISC | Profils Debian désactivés comme à l'installation (`disable_stale_apparmor`), réactivés au retour en 2.6 |
| Redémarrage automatique des services par le paquet ISC | Attendu : Kea est arrêté avant l'installation, la configuration est déjà en place |

**Tests**

- Unitaires : chaque règle de l'analyse sur des configurations réelles (Debian 2.6.3 de la production anonymisée en `example.lan`, HA TLS, D2 avec `secret`, `kea-ctrl-agent`) ; conversion idempotente ; liste des paquets selon la source ; construction du plan et de ses étapes ; retour arrière à chaque étape ; machine d'état de `kea.migration`.
- Démons : `kea-dhcp4 -t` des configurations produites avec le Kea 3.2 de l'hôte de développement ; validation à blanc avec des binaires extraits d'un paquet ; fichier de baux écrit par 2.6 relu par 3.x et l'inverse (format memfile).
- Labo : `tests/lab/test_kea_migration_lab.py` sur la paire ns1 / ns2 en Kea 2.6.3 Debian, HA hot-standby en TLS, D2, et le client DHCP du labo qui renouvelle en boucle : analyse, préparation, migration vers ISC 3.2 ; mesure de la coupure (aucun DHCPNAK, aucun doublon d'adresse, baux du temps 1 présents sur S) ; DDNS qui marche après ; retour arrière forcé au temps 2 ; migration complète puis retour de la paire en 2.6. Variante sur la VM Rocky avec les dépôts `el`. Depuis 0.3.1 (point 82) : `test_kea_migration_p82_lab.py` sur une paire aux noms d'interface différents (la carte du standby renommée `lan0`), et une paire amd64 + arm64 émulé : migration complète et retour, échec forcé après chaque étape des temps 1 et 2, puis échec dans dpkg pendant l'installation (postinst cible en erreur, paquets à moitié configurés), avec retour automatique réel (paquets 2.6 conservés, `/etc/kea`, liens AppArmor, unités, surcharges dpkg et modes des dossiers identiques, sommes comparées, aucun paquet `rc`, paire en hot-standby), et « Constater l'état réel » depuis l'état laissé par 0.3.0 et remis en état à la main.

### 13.5 Surveillance du résolveur (point 60)

**Besoin**

La production résout en récursif, sans forwarder. Quand l'accès aux serveurs racine ou à un TLD se dégrade, ou que la validation DNSSEC échoue, tout le réseau le ressent avant que quelqu'un sache pourquoi. Pelagos doit montrer la santé du résolveur dans le temps, alerter avec des seuils raisonnables, et proposer un repli temporaire vers des forwarders choisis, puis le retour.

**Ce qui existe et sur quoi on s'appuie**

- Le point 23 a livré l'alerte `resolver_health` (`collector/checks/resolver.py`) : taux de SERVFAIL rendus aux clients, échecs de validation (`ValFail`), chute du nombre de requêtes, sonde de la racine (un TLD aléatoire demandé au résolveur local avec CD, sujet `resolver:roots`), avec les seuils `checks.resolver_*`.
- Le statistics-channel est lu à chaque passage (`connectors/bind/stats.py`, `BindInstanceStats.resstats`, vues comprises) ; les compteurs cumulatifs passent par `CounterSeries`.
- L'écran DNS, Résolveur (`ResolverPage.jsx`, `GET /dns/resolver`, `POST /dns/resolver/plan`) lit et écrit déjà `recursion`, `allow-recursion`, `forwarders`, `forward`, `dnssec-validation` par plan.

**Faits vérifiés** (sources lues le 2026-10-28)

- Compteurs du résolveur dans le statistics-channel ([ARM BIND 9.20, Resolver Statistics Counters](https://gitlab.isc.org/isc-projects/bind9/-/blob/bind-9.20/doc/arm/reference.rst)) : `Queryv4`, `Queryv6` (requêtes envoyées), `Responsev4`, `Responsev6`, `NXDOMAIN`, `SERVFAIL`, `REFUSED`, `FORMERR`, `OtherError` (réponses reçues des serveurs distants), `EDNS0Fail`, `Mismatch` (« may be an indication of a cache poisoning attempt »), `Truncated`, `Lame`, `Retry`, `QueryTimeout`, `ValAttempt`, `ValOk`, `ValNegOk`, `ValFail`, histogramme `QryRTTnn` (dernier seau `nn+`), `NumFetch`, `ZoneQuota`, `ServerQuota`, `ClientQuota`, `Priming`.
- Cache, relevé sur le BIND 9.20 de l'hôte de développement (`/json/v1`, `views/<vue>/resolver/cachestats`) : `CacheHits`, `CacheMisses`, `QueryHits`, `QueryMisses`, `DeleteLRU`, `DeleteTTL`, `CoveringNSEC`, `CacheNodes`, `TreeMemInUse`, `HeapMemInUse`. Les noms de seaux `QryRTT` présents dépendent du trafic (seuls les seaux non nuls apparaissent).
- `forward ( first | only )` et `forwarders [ port ] [ tls ] { adresse [ port ] [ tls nom ]; }` en 9.20 (même ARM) : un repli peut aussi passer par DNS sur TLS.
- Adresses publiques de référence : Quad9 avec filtrage et DNSSEC `9.9.9.9`, `149.112.112.112`, `2620:fe::fe`, `2620:fe::9`, TLS `dns.quad9.net` ([Quad9](https://quad9.net/service/service-addresses-and-features/)) ; Cloudflare `1.1.1.1`, `1.0.0.1`, `2606:4700:4700::1111`, `2606:4700:4700::1001` ([Cloudflare](https://developers.cloudflare.com/1.1.1.1/ip-addresses/)).

**Décisions**

1. Mesures par nœud, à chaque passage, gardées comme séries (nouvelle table `resolver_samples` du cache SQLite, rétention `retention.resolver_raw_days` 7 puis moyennes horaires `retention.resolver_hourly_days` 90) :
   - requêtes sortantes par seconde (`Queryv4` + `Queryv6`), délais dépassés (`QueryTimeout`) et nouvelles tentatives (`Retry`) en pourcentage des requêtes sortantes ;
   - latence vers les serveurs distants : p50 et p95 estimés depuis l'histogramme `QryRTT` (interpolation dans le seau, borne haute du dernier seau prise à 2 × sa borne basse) ;
   - SERVFAIL rendus aux clients (déjà mesuré) et reçus des serveurs distants, `Lame`, `EDNS0Fail` ;
   - DNSSEC : `ValAttempt`, `ValOk`, `ValNegOk`, `ValFail` et le taux d'échec ;
   - cache : taux de réussite `QueryHits / (QueryHits + QueryMisses)`, nœuds et mémoire du cache, expulsions `DeleteLRU` (un cache trop petit expulse) ;
   - `Mismatch` (réponses qui ne correspondent pas, tentative d'empoisonnement possible), quotas atteints (`ZoneQuota`, `ServerQuota`, `ClientQuota`).
2. Sondes actives, depuis le nœud, toutes les `probe_interval_seconds` (300) dans les contrôles lents (hors de la boucle de sondage) :
   - racine : requête non récursive `. SOA` vers chaque serveur racine, en IPv4 et en IPv6 si le nœud a une route IPv6, adresses lues par le résolveur local (`. NS` puis A et AAAA), jamais codées en dur ; temps de réponse et joignabilité par lettre ;
   - TLD : pour chaque TLD de `probe_tlds` (défaut : `com`, `net`, `org`, `arpa` et le TLD de chaque zone que le cluster sert), requête non récursive `<tld>. SOA` vers deux des serveurs du TLD ;
   - la sonde existante du résolveur local (TLD aléatoire) reste celle qui lève `resolver:roots`.
   Coût : une quarantaine de petites requêtes toutes les 5 minutes.
3. Alertes (genre existant `resolver_health`, sujets nouveaux) : `resolver:latency` (p95 au-dessus du seuil), `resolver:timeouts` (part de délais dépassés), `resolver:tld:<tld>` (TLD injoignable sur tous ses serveurs sondés pendant `resolver_tld_failures` sondes), `resolver:root-letters` (info : une partie des serveurs racine ne répond pas), `resolver:mismatch` (avertissement au-delà d'un volume), `resolver:cache` (info : expulsions LRU continues). Les seuils par défaut sont prudents, sans données de référence (question 2), et l'écran montre pour chaque seuil la valeur observée sur 7 jours pour qu'on les règle.
4. Repli vers des forwarders : un plan « Passer temporairement par des forwarders », proposé par les alertes `resolver:roots`, `resolver:tld:*`, `resolver:timeouts` et `resolver:latency` critiques, jamais appliqué seul (option `fallback_auto_enabled`, défaut faux). Le plan écrit `forward first` (le résolveur reprend la récursion si les forwarders tombent aussi) et les forwarders choisis dans les options gérées par Pelagos, sur les nœuds choisis (défaut : tous), avec une échéance obligatoire (`fallback_max_hours`, défaut 24). Préréglages : Quad9 (avec filtrage, DNSSEC), Quad9 sans filtrage, Cloudflare, et une liste libre (par exemple les serveurs du fournisseur d'accès) ; DNS sur TLS en option quand le préréglage le permet.
5. Retour : l'état du repli vit dans `cluster.toml` (`resolver.fallback` : nœuds, forwarders, valeurs d'avant de `forward` et `forwarders`, début, échéance, auteur). Le retour est proposé dès que les sondes directes de la racine et des TLD sont saines depuis `fallback_return_healthy_minutes` (15), et appliqué seul à l'échéance (`fallback_auto_return_enabled`, défaut vrai) : la confirmation du plan de repli portait déjà l'échéance, le retour remet exactement les valeurs d'avant. Un changement manuel des forwarders pendant le repli annule le retour automatique (constat affiché).
6. Les forwarders par zone (`type forward` dans `named.conf.local`) ne sont pas touchés ; le point 65 les compare entre nœuds.

**Écrans**

- DNS, Résolveur, nouvelle partie « Santé » en tête de la page existante : par nœud, tuiles (requêtes sortantes par seconde, p95, SERVFAIL, échecs DNSSEC, taux de cache), courbes sur 1 h, 24 h, 7 jours ; table des serveurs racine (lettre, IPv4, IPv6, temps de réponse, dernier échec) et des TLD sondés.
- Bandeau quand un repli est actif : forwarders, nœuds, échéance, boutons « Revenir maintenant » et « Prolonger ».
- Formulaire de repli (`FormModal`) : préréglage, adresses, `first` ou `only`, nœuds, durée.
- Tableau de bord : tuile Résolveur (p95, SERVFAIL, état du repli).

**API**

| Méthode, chemin | Permission | Requête | Réponse |
| --- | --- | --- | --- |
| `GET /dns/resolver/health` | `read:dns` | `?node_id=` | `{"nodes": [{"node_id","sampled_at","rates": {"queries_out","timeouts_percent","servfail_out_percent","servfail_clients_percent","valfail_percent","cache_hit_percent"},"latency_ms": {"p50","p95"},"cache": {"nodes","memory_bytes","lru_per_minute"},"roots": [{"letter","address","rtt_ms","ok","last_failure"}],"tlds": [{"tld","servers","ok","rtt_ms","last_failure"}]}], "fallback": Fallback|null, "thresholds": {...}}` |
| `GET /series/resolver` | `read:series` | `?node_id=&metric=&from=&to=&step=` | séries, même forme que `/series/pools` |
| `POST /dns/resolver/fallback/plan` | `write:dns.config` | `{"forwarders": [...], "forward": "first"|"only", "node_ids"?, "hours", "preset"?, "tls_name"?}` | `Plan` composite (une partie BIND par nœud, `requires_confirmation`) |
| `POST /dns/resolver/fallback/return/plan` | `write:dns.config` | `{}` | `Plan` qui remet les valeurs d'avant |
| `PUT /dns/resolver/fallback` | `write:dns.config` | `{"until"}` | `{"fallback"}` (prolonger, borné par `fallback_max_hours`) |

Les routes de lecture agrègent les nœuds par une action de pair `resolver.health` (même modèle que `alerts.list`). Audit : `dns.resolver.fallback|return|extend`.

**Réglages**

`[settings.resolver]` (nouveau domaine) : `probe_interval_seconds` (300), `probe_tlds` (`["com","net","org","arpa"]`, plus les TLD servis), `probe_ipv6_enabled` (vrai), `fallback_auto_enabled` (faux), `fallback_after_seconds` (600), `fallback_max_hours` (24), `fallback_auto_return_enabled` (vrai), `fallback_return_healthy_minutes` (15). Écrit par l'écran : `resolver.fallback`, `resolver.presets`. Seuils dans `[settings.checks]` : `resolver_latency_warning_milliseconds` (800, sur le p95), `resolver_latency_critical_milliseconds` (1 600), `resolver_timeouts_warning_percent` (10), `resolver_timeouts_critical_percent` (30), `resolver_tld_failures` (3), `resolver_mismatch_warning_count` (100 par fenêtre), `resolver_lru_info_per_minute` (100). Rétention : `retention.resolver_raw_days` (7), `retention.resolver_hourly_days` (90).

**Plusieurs nœuds**

Chaque nœud mesure et sonde pour lui-même (deux résolveurs peuvent ne pas avoir le même accès) ; l'API agrège. Le repli s'applique par nœud dans un plan composite ; le retour automatique est fait par le collecteur de chaque nœud concerné pour sa propre partie, à l'échéance lue dans `resolver.fallback` répliqué : un nœud hors ligne à l'échéance revient à son retour.

**Sécurité**

- Les sondes n'interrogent que la racine, les TLD et le résolveur local ; aucune donnée des clients n'en sort.
- Le repli change l'endroit où partent toutes les requêtes du réseau : `requires_confirmation`, préréglages documentés (filtrage, journalisation de chaque service), DNS sur TLS proposé. `dnssec-validation` n'est jamais désactivé par le repli.

**Pannes**

| Panne | Comportement |
| --- | --- |
| Statistics-channel injoignable | Mesures absentes et dites dans l'écran ; `daemon_down` ou alerte de collecte existantes |
| Pas de route IPv6 | Sondes IPv6 sautées, pas d'alerte |
| Forwarders du repli injoignables aussi | `forward first` : la récursion reprend ; les alertes restent levées |
| Nœud hors ligne à l'échéance du repli | Retour appliqué par son collecteur à son retour |
| Horloge fausse | Échéance comparée à l'horloge locale ; `clock_unsynchronized` existe |

**Tests**

- Unitaires : percentiles depuis un histogramme `QryRTT` (seaux absents, dernier seau) ; taux sur des compteurs remis à zéro (redémarrage de named) ; règles d'alerte et seuils ; choix des TLD sondés ; sonde racine et TLD contre un faux serveur DNS en mémoire ; plan de repli et de retour (valeurs d'avant restituées à l'identique, absence d'origine) ; échéance et retour automatique ; agrégation de cluster ; API.
- Démons : named réel récursif dont les « serveurs racine » sont un second named local (`hint` vers 127.0.0.1) : arrêt du faux serveur racine, `resolver:roots` levée, plan de repli vers un troisième named forwarder, résolution rétablie, retour automatique à l'échéance.
- Labo : sur ns1 / ns2, coupure de l'accès DNS sortant par une règle nftables temporaire sur la VM, alertes, repli vers Quad9 bloqué puis rétabli, retour ; vérification que les seuils par défaut ne lèvent rien sur une semaine de trafic normal du labo (exécution hebdomadaire).

### 13.6 Mise à jour de Pelagos depuis l'interface (point 61)

**Besoin**

Mettre à jour un cluster demande aujourd'hui `scripts/deploy-prod.sh` depuis une machine qui joint chaque nœud en ssh avec `sudo`. L'interface doit montrer la version disponible et ses notes, puis faire la même chose nœud par nœud : vérifier le paquet, sauvegarder l'état, installer, attendre la santé et la convergence, contrôler la HA et les journaux, s'arrêter au premier problème, et savoir revenir à la version précédente. La même mécanique doit servir aux mises à jour de sécurité des paquets BIND et Kea de la distribution.

**Ce qui existe et sur quoi on s'appuie**

- `scripts/deploy-prod.sh` et `docs/user/upgrade.md` fixent la procédure : sommes SHA256, sauvegarde de `/etc/pelagos` et `/var/lib/pelagos` hors `series.sqlite`, installation, `settle` de 30 s, attente de `/api/v1/health`, contenu de `cluster.toml` identique (empreinte du contenu analysé, sans l'en-tête), nombre d'entrées d'audit égal et jamais en baisse, unités relancées (identifiant d'invocation différent), aucune ligne `ERROR` des nouveaux processus, HA Kea dans un état normal ; nœuds non primaires d'abord ; refus d'une version plus ancienne (retour arrière manuel).
- Le cas de deux versions dans le cluster est pris en charge et documenté (« While two versions run »).
- L'assistant privilégié (`pelagos helper`, socket `root:pelagos` 0660) exécute déjà comme root, par une liste fermée d'opérations, les installations de paquets (`platform/packages.py`, apt et dnf).
- Le point 37 lit la version installée et la candidate des paquets BIND et Kea (`collector/checks/distro.py`, `apt-cache policy`, `dnf updateinfo`) et le suivi de sécurité de Debian.
- Les releases sont des répertoires `make release` : debs amd64 et arm64, `SHA256SUMS`, `NOTES.md`, joints à la release GitHub ; `release.json` et `SHA256SUMS.sig` depuis la 0.3.0 (U1).

**Décisions**

1. Sources de version, au choix dans l'écran :
   - dépôt de release téléversé : l'administrateur dépose les fichiers d'un répertoire de release (paquets, `SHA256SUMS`, `SHA256SUMS.sig`, `NOTES.md`) ; marche sans accès Internet et avec un dépôt privé ;
   - URL de releases : l'API des releases GitHub (`GET /repos/{owner}/{repo}/releases/latest`), jeton optionnel pour un dépôt privé, rangé en secret ; vérifiée tous les `check_interval_hours` par le nœud de service (13.1, décision 1) ;
   - dépôt apt ou dnf de Pelagos, quand il existera : lu par `apt-cache policy pelagos`, installé par le gestionnaire de paquets.
2. Signature vérifiée, release non signée acceptée sur confirmation (décision de l'utilisateur du 2026-10-30, qui remplace « signature obligatoire ») : `make release` signe `SHA256SUMS` par une clé Ed25519 de release (`SHA256SUMS.sig`) quand une clé est disponible, sans erreur sinon ; les clés publiques acceptées sont livrées dans le paquet (`pelagos/data/release-keys/`, propriété de root) ; la vérification se fait dans l'assistant privilégié, jamais seulement dans le processus web : sinon le groupe `pelagos` pourrait faire installer un paquet quelconque par root. L'assistant refuse aussi tout paquet qui ne s'appelle pas `pelagos`, une architecture différente, ou une version qui n'est ni plus récente que l'installée ni la précédente notée pour un retour. Une nouvelle clé est livrée dans une release signée par l'ancienne. Une release sans signature, ou signée par une clé inconnue, s'installe depuis l'interface après un avertissement clair dans l'aperçu (« release non signée : son origine n'est pas vérifiée ») et une confirmation explicite en plus de la confirmation normale (case cochée et version saisie), avec l'entrée d'audit `update.unsigned_accepted` au nom de l'utilisateur. Les sommes de `SHA256SUMS` sont toujours vérifiées ; une signature présente mais invalide reste un refus (fichier altéré). Formats et règles : architecture, section 29.
3. Le déroulé est tiré, pas poussé : le plan « Mettre à jour vers 0.2.4 » écrit un déroulé dans `cluster.toml` (`updates.rollout` : identifiant, version, sommes des paquets par architecture, ordre des nœuds, état de chaque nœud, auteur, options). Le collecteur de chaque nœud regarde ce déroulé ; quand vient son tour (tous ceux d'avant `done`, cluster sain), il récupère les paquets chez le nœud qui les a (`GET /repl/v1/releases/<version>/<fichier>`, mTLS), les vérifie, et demande à son assistant privilégié de faire sa mise à jour. Aucun nœud ne pilote les autres : le redémarrage du nœud où l'administrateur a cliqué ne casse rien.
4. Survivre à son propre redémarrage : l'assistant lance la mise à jour dans une unité transitoire (`systemd-run --unit=pelagos-upgrade-<id> pelagos upgrade apply --rollout <id>`), indépendante de `pelagos.service`, `pelagos-collector.service` et de la connexion à l'assistant. Elle écrit sa progression dans `/var/lib/pelagos-helper/upgrade/<id>/<nœud>.json` (root, lisible par le groupe `pelagos`) : arrêt des services, sauvegarde de l'état, installation, version vérifiée. Les nouveaux processus relisent ce fichier, font les contrôles d'après installation et écrivent l'état du nœud dans `updates.rollout`. L'interface perd sa connexion quelques secondes, se reconnecte (`/health`), redemande la session si elle a été perdue, et reprend l'affichage depuis l'état répliqué.
5. Contrôles par nœud, repris de `deploy-prod.sh` : avant (santé de tout le cluster, empreinte de `cluster.toml`, compte d'audit, HA Kea), sauvegarde (`/var/lib/pelagos-helper/upgrade/backups/pelagos-state-<date>-<ancienne version>.tar.gz`, 0600 root, plus une archive 13.2 si une destination existe), installation, version installée, attente de `settle_seconds` puis jusqu'à `timeout_seconds` de la santé et de la convergence, audit jamais en baisse, unités relancées, aucune ligne `ERROR` des nouveaux processus (lue par l'assistant, opération `journal_errors`). Le nœud suivant attend `pause_seconds` (défaut 60) après le `done` du précédent.
6. Ordre par défaut : les nœuds qui ne sont ni primaire DNS actif (`ddns.roles` et zones primaires) ni primaire de la HA Kea, puis ceux-là, le primaire DNS en dernier ; modifiable dans l'aperçu.
7. Arrêt au premier problème : le nœud passe `failed` avec l'étape et la raison, les suivants ne démarrent pas ; alerte `update_failed` (critical) et notification (13.1). Actions : « Reprendre » (après correction), « Annuler le reste » (les nœuds faits restent sur la nouvelle version, état mixte pris en charge), « Revenir en arrière ».
8. Retour arrière :
   - automatique sur le nœud qui échoue après son installation (`auto_rollback_enabled`, défaut vrai) quand la release déclare la même version d'état que la précédente (`release.json`, champ `state_schema`) : réinstallation du paquet précédent, gardé dans `/var/lib/pelagos-helper/upgrade/packages/` à chaque mise à jour, suppression de `series.sqlite` (cache), redémarrage, mêmes contrôles ;
   - quand `state_schema` a changé (migration de réglages, de format) : pas de retour automatique ; l'écran donne la procédure de `upgrade.md` (`pelagos settings --legacy`, restauration de la sauvegarde d'état du nœud) et propose les étapes qu'il sait faire ;
   - « Revenir en arrière » pour tout le cluster : déroulé inverse vers la version précédente, dans l'ordre inverse, sous les mêmes conditions.
   Le tout premier passage par l'interface n'a pas de paquet précédent gardé si la version d'avant a été installée à la main : l'écran le dit et accepte le dépôt du paquet précédent.
9. Paquets des moteurs (option demandée) : même déroulé, de genre `engine_packages`, pour une mise à jour dans la même série de la distribution (BIND 9.20.x, Kea 2.6.x de Debian, ou Kea de la même série ISC), proposée par `security_advisory` quand une version corrigée est candidate (point 37) ou manuellement. Ordre : secondaires DNS puis primaire ; pour Kea, `ha-maintenance-start` envoyé au pair avant l'installation et `ha-maintenance-cancel` après le retour en état normal, standby d'abord. Contrôles : version relue, `rndc status`, transferts de zone à jour, `status-get` de la HA, alertes nouvelles. Un changement de série de Kea passe par 13.4, jamais par ici.
10. Docker : pas de mise à jour depuis l'interface ; l'écran donne la version de l'image et la commande `docker compose pull && docker compose up -d`.

**Écrans**

- Administration, Mises à jour : version de chaque nœud, version disponible (source, date, notes rendues depuis `NOTES.md`), état de la signature, bouton « Préparer la mise à jour ».
- Aperçu : ordre des nœuds (réordonnable), contrôles qui seront faits, durée estimée, option de retour automatique, confirmation par mot de passe.
- Déroulé : frise des nœuds avec l'étape de chacun en direct, journal des étapes, état des contrôles, boutons Reprendre, Annuler le reste, Revenir en arrière ; page qui se reconnecte seule après le redémarrage du nœud courant.
- Onglet « Paquets des moteurs » : par nœud, BIND et Kea installés et candidats, CVE corrigées par la candidate, bouton « Mettre à jour » qui ouvre le même aperçu.
- Historique : déroulés passés, par version et par nœud.

**API**

| Méthode, chemin | Permission | Requête | Réponse |
| --- | --- | --- | --- |
| `GET /admin/updates` | `admin:updates` | | `{"nodes": [{"node_id","version","arch","package_format","previous_kept"}],"available": [{"version","source","published_at","notes","signed","state_schema"}],"rollout": Rollout|null,"settings","engines": [{"node_id","engine","package","installed","candidate","cves"}]}` |
| `POST /admin/updates/check` | `admin:updates` | | `{"available"}` (vérification immédiate) |
| `POST /admin/updates/upload` | `admin:updates` | multipart : fichiers d'un répertoire de release | `{"version","files","signature","signed"}` (`signature` : `valid`, `unsigned` ou `unknown_key`) ou `422 release_invalid` (signature invalide, somme, nom) |
| `PUT /admin/updates/settings` | `admin:updates` | `[settings.updates]` partiel, `github_repository`, `github_token` | `{"settings"}` |
| `POST /admin/updates/plan` | `admin:updates` | `{"kind": "pelagos"|"engine_packages"|"rollback","version"?,"packages"?,"order"?,"auto_rollback"?,"accept_unsigned"?,"confirm_version"?}` | `Plan` (scope `update`, `requires_confirmation`, mot de passe exigé à l'application) |
| `GET /admin/updates/rollout` | `admin:updates` | | `Rollout` : `{"id","kind","version","state","order","nodes": [{"node_id","state","step","started_at","finished_at","error"}],"created_by"}` |
| `POST /admin/updates/rollout/{id}/action` | `admin:updates` | `{"action": "resume"|"cancel"|"rollback"}` | `Rollout` |
| `GET /admin/updates/history?page=&per_page=` | `admin:updates` | | paginé |

Nouvelle permission `admin:updates` (rôle administrateur), nouveau scope de plan `update`. Réplication : `GET /repl/v1/releases/<version>/<fichier>` (mTLS, fichiers d'une release téléversée). Assistant privilégié, opérations nouvelles : `update_verify` (signature, sommes, nom, version), `update_start` (unité transitoire), `update_status`, `journal_errors`. Audit : `admin.update.plan|resume|cancel|rollback`, `update.unsigned_accepted`, `update.node.start|done|failed|rolled_back`.

**Réglages**

`[settings.updates]` (nouveau domaine) : `check_enabled` (vrai), `check_interval_hours` (24), `source` (`"upload"`, `"github"` ou `"repository"`), `github_repository` (vide), `settle_seconds` (30), `timeout_seconds` (300), `pause_seconds` (60), `auto_rollback_enabled` (vrai), `keep_packages_count` (2). Écrit par l'écran : `updates.rollout`. Secret : `updates/github_token`. Alertes : `update_available` (info, sujet `update:pelagos`), `update_failed` (critical, sujet `update:<rollout>`), `update_stalled` (warning : un nœud n'a pas avancé depuis 2 × `timeout_seconds`), `version_mismatch` existante pendant le déroulé (sans nouvelle notification tant qu'un déroulé est actif).

**Plusieurs nœuds**

Le déroulé et les états sont dans `cluster.toml`, répliqués ; chaque nœud n'écrit que sa propre ligne (pas de conflit d'écriture). Les nœuds d'une version qui ne connaît pas `updates` ignorent la section ; la première version qui sait se mettre à jour s'installe donc à la main ou par `deploy-prod.sh`, qui reste l'outil de secours et le modèle des contrôles. Pendant le déroulé, deux versions coexistent ; les limites sont celles de `upgrade.md`.

**Sécurité**

- Signature et règles vérifiées par root dans l'assistant (décision 2) ; accepter une release non signée revient à laisser un administrateur (et le groupe `pelagos`, qui écrit `cluster.toml`) faire installer par root n'importe quel paquet nommé `pelagos` : compromis choisi par l'utilisateur le 2026-10-30, rendu explicite par l'avertissement, la version saisie, le mot de passe et l'audit ; paquets rangés en 0600 root ; jamais d'installation depuis une URL donnée par le client.
- `admin:updates` plus le mot de passe de l'utilisateur à la confirmation ; audit complet ; un seul déroulé actif à la fois.
- Les sauvegardes d'état contiennent la clé maître et la CA : 0600 root, jamais copiées vers un pair, purgées après `keep_packages_count` mises à jour.
- Jeton GitHub stocké chiffré, lecture seule recommandée (permission Contents en lecture).

**Pannes**

| Panne | Comportement |
| --- | --- |
| Signature invalide ou somme invalide | Refus avant tout changement, alerte, audit |
| Release non signée ou clé inconnue | Avertissement, confirmation supplémentaire, audit `update.unsigned_accepted` |
| Installation en échec | Nœud `failed` ; paquet précédent toujours en place (le gestionnaire n'a rien changé) ou retour automatique |
| Nouveaux processus en échec (santé, `ERROR`, convergence) | Retour automatique si `state_schema` identique, sinon arrêt et procédure affichée |
| Coupure de l'interface pendant le redémarrage | Reconnexion, état relu depuis `updates.rollout` ; rien ne dépend de la page |
| Nœud injoignable pendant son tour | `update_stalled`, déroulé en attente ; « Annuler le reste » possible |
| Redémarrage de la machine pendant l'installation | L'unité transitoire n'existe plus ; au démarrage, le collecteur trouve le fichier de progression inachevé et passe le nœud `failed` avec l'état du paquet relu (`dpkg --audit`, `rpm -V`) |
| Deux déroulés lancés en même temps | Le second est refusé (`409 conflict`) ; une coupure réseau ne peut en créer deux que si deux administrateurs agissent chacun de son côté : le second voit l'autre à la reconnexion et est mis en attente |

**Tests**

- Unitaires : signature Ed25519 de `SHA256SUMS` (bonne, mauvaise, clé inconnue, rotation de clé) ; règles de l'assistant (nom, architecture, version, chemin) ; machine d'état du déroulé (tour de chaque nœud, arrêt, reprise, annulation, retour) ; contrôles d'après installation sur des états factices (repris des sondes de `deploy-prod.sh`) ; ordre par défaut ; lecture des releases GitHub sur un faux serveur ; API.
- Démons : deux collecteurs réels et une fausse commande d'installation qui remplace le paquet par une version marquée : déroulé complet, échec provoqué sur le second nœud, retour automatique.
- Labo : `tests/lab/test_upgrade_ui_lab.py` sur ns1 (amd64) et ns2 (arm64 émulé) : mise à jour d'une release construite par `make release NO_TAG=1` et signée par une clé de test, par l'API comme le ferait l'interface ; mêmes vérifications que `test_upgrade_lab.py` (audit, `node.toml`, réplication dans les deux sens, HA) ; puis un paquet volontairement cassé (unité qui ne démarre pas) et retour automatique ; puis paquets des moteurs : mise à jour de BIND d'une version Debian à la suivante (dépôt local du labo). Le même scénario sur la VM Rocky avec les rpm.

### 13.7 IPv6 : AAAA et PTR (point 62)

**Besoin**

Les machines du réseau ont des adresses IPv6 globales obtenues par SLAAC, sans DHCPv6 : aucun AAAA ni PTR n'est créé pour elles, et rien ne le signale. Pelagos doit observer les adresses réellement utilisées, distinguer les adresses stables des adresses temporaires de confidentialité, dire quels hôtes connus en IPv4 n'ont pas d'AAAA, et proposer la création des AAAA et des PTR hôte par hôte, par plan.

**Ce qui existe et sur quoi on s'appuie**

- Les contrôles de cohérence (`services/consistency.py`) lèvent déjà `ptr_mismatch` pour un AAAA sans PTR quand la zone inverse IPv6 est gérée, et les PTR orphelins (vue « PTR orphelins »).
- La vue Hôtes joint bail, réservation et enregistrements A, AAAA, PTR par MAC, puis adresse, puis nom (`services/hosts_service.py`) ; les plans d'hôte écrivent enregistrements et réservations.
- Les exceptions génériques (`[[exceptions]]`) et le nœud de service (13.1, décision 1).
- DHCPv6 est un module optionnel ; ses baux suivent déjà le chemin des baux IPv4.

**Faits vérifiés** (sources lues le 2026-10-28)

- Adresses temporaires (RFC 8981, section 3.8) : `TEMP_VALID_LIFETIME` 2 jours et `TEMP_PREFERRED_LIFETIME` 1 jour par défaut ([RFC 8981](https://www.rfc-editor.org/rfc/rfc8981.html)). Une adresse encore utilisée au-delà de sa durée de validité n'est donc pas une adresse temporaire aux réglages par défaut.
- Windows et macOS gardent une adresse temporaire valide 7 jours (préférée 1 jour) : `maxvalidlifetime` « default is seven days » de `netsh interface ipv6 set privacy` ([Microsoft, netsh interface](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/netsh-interface), lu le 2026-10-29) ; `DEF_TEMP_VALID_LIFETIME 604800` dans `bsd/netinet6/nd6.h` de XNU ([apple-oss-distributions/xnu](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet6/nd6.h), lu le 2026-10-29). Une adresse dépréciée tenue par une connexion longue reste dans les tables de voisins jusqu'à 7 jours : le seuil `stable_min_days` est donc de 8 jours.

**Décisions**

1. Sources d'observation, génériques seulement (aucun connecteur de routeur) :
   - table des voisins de chaque nœud (`ip -j -6 neigh show`, lisible sans privilège) : voit les machines qui parlent au nœud en IPv6 (requêtes DNS sur l'adresse IPv6 du nœud, découverte de voisins) ; active par défaut, aucun réglage ;
   - baux DHCPv6 de Kea (module DHCPv6) : déjà connus, lus toutes les `poll_seconds` (300).
   La source OPNsense de la 0.2.2 est retirée en 0.2.3 (point 71 : trop spécifique pour un DDI) : au démarrage, chaque nœud efface `ipv6.sources` et les secrets `ipv6/source/...` de cluster.toml, une seule écriture notée dans l'audit par `system` ; ce qu'un pair 0.2.2 envoie encore (entrée réécrite, observations ou statuts `opnsense`) est ignoré.
   Chaque observation est `(mac, adresse, source, nœud, premier vu, dernier vu, état)`, gardée dans le cache SQLite du nœud qui l'a faite (`ipv6_observations`, rétention `retention.ipv6_observation_days` 30).
2. Filtre des adresses : lien local (`fe80::/10`), multicast, adresses hors des préfixes surveillés ignorés. Préfixes surveillés (`ipv6.prefixes`) : par défaut ceux des zones inverses IPv6 que le cluster sert et des sous-réseaux DHCPv6 ; les ULA (`fd00::/8`) seulement si un préfixe ULA est listé.
3. Classement de chaque adresse :
   - `eui64` : l'identifiant d'interface est l'EUI-64 de la MAC observée (bit U/L inversé, `ff:fe` au milieu) : stable ;
   - `stable` : vue pour la même MAC depuis plus de `stable_min_days` (8 jours, au-dessus des 7 jours de validité d'une adresse temporaire sous Windows et macOS) et encore vue dans les dernières 24 h ;
   - `temporary` : plusieurs adresses pour la même MAC et le même préfixe, chacune vue moins longtemps, remplacées au fil des jours (disparue depuis un jour, ou suivie d'une plus récente) ; jamais proposée ; une adresse courante que rien n'a encore remplacée reste `unknown` ;
   - `unknown` : pas encore assez d'historique ; proposée seulement si l'administrateur la choisit.
   Une MAC aléatoire (bit « localement administré ») est signalée : son nom peut changer de réseau en réseau.
4. Rattachement à un nom : la MAC mène à l'hôte de la vue Hôtes (bail ou réservation IPv4, nom du bail, A existant). Le nom proposé est le propriétaire de l'A de l'hôte dans sa zone directe ; sans A ni nom de bail, l'adresse est listée « hôte inconnu », sans proposition.
5. Contrôles (alertes groupées pour ne pas noyer la page) :
   - `ipv6_missing_aaaa` (info, une alerte par zone directe, sujet `ipv6:aaaa:<zone>`) : hôtes avec une adresse stable observée et sans AAAA ; le détail liste les hôtes ;
   - `ipv6_reverse_missing` (info, sujet `ipv6:reverse:<préfixe>`) : préfixe surveillé sans zone inverse servie ; propose la création de la zone (plan de zone existant, dynamique, `update-policy` comme les autres) ;
   - `ipv6_stale_aaaa` (warning, sujet `ipv6:stale:<zone>`) : AAAA dans un préfixe surveillé dont l'adresse n'est plus observée depuis `stale_days` (14) alors que la MAC de l'hôte est vue avec une autre adresse stable ; cas typique : changement de préfixe chez le fournisseur d'accès, où l'alerte propose de remplacer en bloc tous les AAAA et PTR de l'ancien préfixe ;
   - un AAAA sans PTR reste `ptr_mismatch`, rien de nouveau.
   Un hôte connu en IPv4 sans aucune adresse IPv6 observée ne lève rien : il peut être en IPv4 seul.
6. Création toujours par plan choisi hôte par hôte : la sélection produit un plan composite (AAAA dans la zone directe, PTR dans la zone inverse, `ddi-admin`, par lots), avec l'aperçu habituel. Un nom tenu par le DDNS (DHCID présent) est signalé : l'AAAA ajouté par Pelagos n'est pas retiré par D2 à l'expiration du bail IPv4 (D2 ne retire que les adresses de son bail), dit dans l'aperçu. Vérifié au labo le 2026-10-30 (kea-dhcp-ddns 2.6.3, BIND 9.20, `tests/lab/test_ipv6_ddns_owner_lab.py`) et conforme à RFC 4703 §5.5 tel que Kea 2.6.3 le construit (`src/bin/d2/nc_remove.cc`, lu le 2026-10-30) : D2 retire l'A, puis refuse de retirer le reste tant qu'un AAAA existe (YXRRSET) ; le DHCID et le PTR IPv4 restent, et un client d'un autre identifiant se voit refuser le nom. L'aperçu le dit, et une MAC aléatoire sur un nom DDNS demande une confirmation. Pas de création automatique dans la première version (`auto_apply_enabled` existe, faux par défaut, réservé à la suite).
7. Exceptions : par hôte (`ipv6_missing_aaaa`, clé `mac:<mac>`) ou par adresse, avec motif, par le mécanisme `[[exceptions]]` existant.

**Écrans**

- Hôtes, nouvel onglet « IPv6 » : une ligne par hôte avec MAC, IPv4, adresses IPv6 observées et leur classe (badge EUI-64, stable, temporaire, inconnue), source et dernière observation, AAAA et PTR actuels, case à cocher ; filtres (sans AAAA, sans PTR, obsolètes, inconnus) ; boutons « Créer AAAA et PTR de la sélection », « Exception ».
- Fiche d'hôte : partie IPv6 avec l'historique des adresses observées.
- Administration, Observation IPv6 : sources génériques (tables des voisins, baux DHCPv6) et leurs réglages, dernier passage de chaque source sur chaque nœud, préfixes surveillés.

**API**

| Méthode, chemin | Permission | Requête | Réponse |
| --- | --- | --- | --- |
| `GET /hosts/ipv6` | `read:hosts` | `?filter=&zone=&host_key=&page=&per_page=` (`host_key` : la fiche d'hôte, lot V5) | paginé `{"host_key","name","mac","mac_random","ipv4","observed": [{"address","class","sources","first_seen","last_seen"}],"aaaa","ptr","ptr_missing","proposal": {"address","class","name","zone","reverse_zone"}|null,"excepted"}` ; une ligne aussi par AAAA des zones jugées que rien n'a observé (0.2.3, point 72) |
| `POST /hosts/ipv6/plan` | `write:dns.records` | `{"items": [{"host_key","address","name"?}]}` | `Plan` composite (AAAA et PTR) |
| `POST /hosts/ipv6/replace-prefix/plan` | `write:dns.records` | `{"old_prefix","new_prefix","zones"?}` | `Plan` composite |
| `POST /hosts/ipv6/reverse-zone/plan` | `write:dns.zones` | `{"prefix","view"?,"node_ids"?}` | `Plan` de zone (zone inverse dynamique proposée par `ipv6_reverse_missing`, lot V4) |
| `GET /admin/ipv6` | `admin:settings` | | `{"prefixes","effective_prefixes","settings","status": [{"source","source_id","node_id","last_poll","error","entries","kept","failing_since","problem"}]}` (architecture.md section 27) |
| `PUT /admin/ipv6` | `admin:settings` | `{"prefixes"}` | idem |

Action de pair `ipv6.observations` (les observations de chaque nœud, agrégées par l'API). Audit : `admin.ipv6.*`, plans habituels.

**Réglages**

`[settings.ipv6]` (nouveau domaine) : `neighbors_enabled` (vrai), `poll_seconds` (300), `stable_min_days` (8), `stale_days` (14), `auto_apply_enabled` (faux). Écrit par l'écran : `ipv6.prefixes`. Rétention : `retention.ipv6_observation_days` (30).

**Plusieurs nœuds**

Chaque nœud observe ses voisins et ses baux DHCPv6 ; l'API fusionne par `(mac, adresse)` en gardant le premier et le dernier vu de toutes les sources. Un nœud hors ligne réduit la vue sans la fausser (l'écran dit quelles sources manquent).

**Sécurité**

- Les observations sont des données personnelles du réseau (adresses et MAC des appareils) : lisibles avec `read:hosts`, jamais envoyées hors du cluster, rétention bornée.
- Les plans n'écrivent que `AAAA` et `PTR`, déjà dans les types de `ddi-admin`.

**Pannes**

| Panne | Comportement |
| --- | --- |
| Source du nœud (ip neigh, baux DHCPv6) en échec | Avertissement une fois, alerte `ipv6_source_failed` après 10 min ; pas pour les baux DHCPv6 tant que `daemon_down` est ouverte pour Kea DHCPv6 |
| Changement de préfixe du fournisseur | `ipv6_stale_aaaa` et plan de remplacement en bloc |
| Zone inverse IPv6 absente | `ipv6_reverse_missing`, création proposée ; les PTR de la sélection sont refusés avant le plan |
| Hôte à MAC aléatoire | Signalé ; proposition possible, avec avertissement |

**Tests**

- Unitaires : analyse de `ip -j -6 neigh` ; détection EUI-64 ; classement sur un historique synthétique (rotation quotidienne d'adresses temporaires, adresse stable opaque, changement de préfixe) ; rattachement MAC vers hôte ; contrôles et exceptions ; plans AAAA et PTR ; remplacement de préfixe ; fusion de cluster ; API.
- Démons : named réel avec zone directe et zone inverse IPv6 dynamiques, application du plan, `ptr_mismatch` refermée.
- Labo : le client du labo en SLAAC sur le réseau du labo (préfixe de documentation annoncé par radvd sur un nœud), adresses temporaires activées (`use_tempaddr=2`) : observation, classement après simulation du temps (horodatages injectés), création des AAAA et PTR de l'adresse stable seulement.

### 13.8 Intégration Home Assistant (point 63) : retirée

Retirée le 2026-10-30 par l'utilisateur : trop spécifique. Les lots H2 à H5 (état et présence, publication MQTT, écran Intégrations, documentation et labo Home Assistant) sont abandonnés et aucun code Home Assistant n'est prévu. Restent livrés et maintenus : le préréglage Home Assistant du webhook de notification (13.1) et les jetons d'API (point 70, section 9), utilisables par tout outil d'automatisation, Home Assistant compris (`rest:` avec un jeton en lecture).

### 13.9 Lots d'implémentation des points 56 à 58

Un lot = un agent, un worktree, ses tests, un commit poussé après `make lint` et les tests des modules touchés. Les lots « contrat » touchent `docs/architecture.md`, `domain/`, le registre des réglages et `docs/contracts-changes.md` ; ils passent en premier et un seul à la fois.

| Lot | Contenu | Paquets | Dépend de |
| --- | --- | --- | --- |
| C1 | Contrat des trois fonctions : sections nouvelles de l'architecture (notifications, archives, reprise DDNS), domaines `notifications`, `archives`, `ddns` et leurs réglages, permissions `admin:notifications` et `admin:archives`, scopes `restore` et `dns.failover`, genres d'alertes, clés de message, routes enregistrées en `501` | contrat, WP-CORE | |
| N1 | Répartiteur : choix de l'expéditeur, événements, regroupement, confirmation, rappels, heures calmes, plafond, file et nouveaux essais, audit `notify.*`, alerte `notification_failed` ; module partagé de vue de cluster | WP-COLLECTOR, WP-CORE | C1 |
| N2 | Transports et rendu : SMTP, ntfy, Gotify, webhook signé, préréglage Home Assistant, Matrix ; catalogues de messages empaquetés côté serveur | WP-CORE | C1 |
| N3 | API des notifications (canaux, test, ordre, silence, historique) | WP-API-AUTH | C1, N2 |
| N4 | Écran Notifications, bannière de silence, « notifiée » dans le détail d'une alerte, en et fr | WP-FRONTEND | C1 (serveur factice), N3 pour l'intégration |
| N5 | Démons et labo : deux collecteurs et relais ; conteneurs ntfy, Gotify, Mailpit, récepteur de webhook ; scénario de panne HA | WP-LAB-E2E | N1 à N3 |
| D1 | Rattrapage seul : opérations `lease4/6-resend-ddns`, sélection des baux d'une fenêtre, plan « Rejouer », alerte `ddns_replay` (utile même sans bascule) | WP-KEA, WP-API-AUTH | C1 |
| D2 | Préparation : contrôle des prérequis, plan composite (clés sur les secondaires, listes de D2, `ddns.roles`), `ddns_advice` qui le propose | WP-BIND, WP-KEA, WP-API-AUTH | C1 |
| D3 | Promotion : réécriture de la copie en texte, déclaration primaire, inversion des listes de D2, autres secondaires repointés, alerte `ddns_outage`, option automatique | WP-BIND, WP-KEA, WP-COLLECTOR | D2 |
| D4 | Retour et changement planifié : rétrogradation au démarrage, `dns_stale_primary`, plan « Rendre le rôle » | WP-COLLECTOR, WP-BIND | D3 |
| D5 | Onglet Reprise, tuile du tableau de bord, badge de zone | WP-FRONTEND | D1 à D4 (serveur factice dès C1) |
| D6 | Démons et labo de la bascule | WP-LAB-E2E | D1 à D4 |
| B1 | Format : age X25519 avec `cryptography`, vecteurs CCTV, interopérabilité avec `age`, tar et manifeste, sommes | WP-CORE | C1 |
| B2 | Collecte et planification : lecture des fichiers et AXFR, opération en lecture de l'assistant privilégié, verrou, stockage local, rétention, vérification, restauration à blanc, alertes | WP-COLLECTOR, WP-INSTALLER | B1 |
| B3 | Destinations : pair (`/repl/v1/archives`), dossier monté, SFTP (S3 plus tard) | WP-CORE, WP-COLLECTOR | B1 |
| B4 | Restauration en ligne : inspection, diff par partie, plan composite `restore` (fichiers gérés, zones par UPDATE ou remplacement, Kea et D2, sections de `cluster.toml`, fusion de l'audit) | WP-API-AUTH, WP-BIND, WP-KEA | B1, B2 |
| B5 | Reconstruction : `pelagos restore` et `pelagos backup` en ligne de commande, documentation d'exploitation | contrat (`cli.py`), WP-INSTALLER | B1, B4 |
| B6 | API et écran Sauvegardes | WP-API-AUTH, WP-FRONTEND | B2 à B4 |
| B7 | Démons et labo : SFTP sur la VM Docker du labo, reconstruction de ns2 | WP-LAB-E2E | B2 à B5 |

Ordre proposé : C1 ; puis en parallèle N1, N2, D1, B1 ; puis N3, N4, D2, B2, B3 ; puis N5 (release 0.2.0 : notifications et rattrapage DDNS) ; D3, D4, D5, D6 (0.2.1 : reprise DDNS) ; B4, B5, B6, B7 (0.2.2 : sauvegardes). Les notifications passent d'abord parce que la bascule DDNS et les sauvegardes s'appuient sur elles pour prévenir.

**Décisions de l'utilisateur** (2026-10-28)

1. Matrix fait partie de la première version des notifications (API client-serveur HTTP simple).
2. Pas de S3 dans la première version ; plus tard, avec un petit client SigV4 écrit à la main, sans `boto3`.
3. Les archives sont chiffrées pour plusieurs destinataires age : l'identité du cluster (scellée par la clé maître, téléchargeable une fois) et, en option, des clés publiques de l'administrateur.
4. Bascule DDNS manuelle par défaut, avec notification ; la promotion automatique après N minutes est une option, désactivée par défaut.
5. Rétrogradation automatique de l'ancien primaire à son retour : activée par défaut.
6. Rattrapage DDNS (`lease*-resend-ddns`) : toujours par un plan confirmé, jamais automatique.
7. Préparer la reprise exige que les zones soient gérées par Pelagos (adoption, point 33) ; l'interface le dit et propose l'adoption.
8. Baux Kea dans les archives par défaut.

### 13.10 Lots des points 59 à 63

Mêmes règles qu'en 13.9 : un lot = un agent, un worktree, ses tests, poussé après `make lint` et les tests des modules touchés ; un lot contrat par release, en premier et seul. Les lots d'écran travaillent sur un serveur factice dès que le contrat est posé.

| Lot | Contenu | Paquets | Dépend de |
| --- | --- | --- | --- |
| C2 | Contrat de la 0.2.2 : sections nouvelles de l'architecture (santé du résolveur et repli, analyse de migration Kea, observations IPv6), domaines `resolver` et `ipv6`, réglages, seuils et rétentions, sujets de `resolver_health`, genres `kea_series_obsolete`, `ipv6_missing_aaaa`, `ipv6_reverse_missing`, `ipv6_stale_aaaa`, clés de message, actions de pair `resolver.health` et `ipv6.observations`, routes en `501` | contrat, WP-CORE | |
| R1 | Mesures du résolveur : lecture des compteurs et du cache, percentiles `QryRTT`, table `resolver_samples` et rétention, `/series/resolver`, alertes `resolver:latency`, `timeouts`, `mismatch`, `cache` | WP-COLLECTOR, WP-BIND | C2 |
| R2 | Sondes de la racine et des TLD (contrôles lents), alertes `resolver:tld:*`, `resolver:root-letters` | WP-COLLECTOR | C2 |
| R3 | Repli et retour : plans composites, `resolver.fallback`, prolongation, retour automatique par le collecteur, `GET /dns/resolver/health` et l'agrégation | WP-API-AUTH, WP-BIND, WP-COLLECTOR | C2, R1 |
| R4 | Écran Santé du résolveur, bandeau et formulaire du repli, tuile du tableau de bord, en et fr | WP-FRONTEND | C2 (factice), R3 |
| R5 | Démons (faux serveurs racine, repli, retour) et labo du résolveur | WP-LAB-E2E | R1 à R3 |
| K1 | Analyse de migration Kea : règles et conversion 2.6 vers 3.x, paquets à retirer et installer selon la source, validation à blanc par binaires extraits (ou repli documenté), rapport | WP-KEA, WP-INSTALLER | C2 |
| K2 | API de l'analyse, alerte `kea_series_obsolete` et date de fin dans le fichier des avis ISC, écran « Migration Kea » en lecture (rapport, diffs) | WP-API-AUTH, WP-COLLECTOR, WP-FRONTEND | K1 |
| V1 | Observations IPv6 : voisins des nœuds, baux DHCPv6 (interface `NeighborSource`), table `ipv6_observations`, classement EUI-64 / stable / temporaire, rattachement aux hôtes | WP-COLLECTOR, WP-CORE | C2 |
| V2 | Contrôles IPv6 et alertes, `GET /hosts/ipv6`, `/admin/ipv6` (sources, test, préfixes ; test et sources retirés en 0.2.3, point 71) | WP-COLLECTOR, WP-API-AUTH | V1 |
| V3 | Onglet IPv6 de la vue Hôtes en lecture (filtres, exceptions), écran Observation IPv6 (Sources IPv6 en 0.2.2) | WP-FRONTEND | C2 (factice), V2 |
| C3 | Contrat de la 0.2.3 : section « mises à jour » de l'architecture, domaine `updates`, permission `admin:updates`, scope `update`, opérations de l'assistant, route `/repl/v1/releases`, `release.json` (`state_schema`) et format de `SHA256SUMS.sig`, alertes `update_*` | contrat, WP-CORE | |
| U1 | Signature des releases : `make release` signe `SHA256SUMS` (clé lue hors du dépôt), clés publiques empaquetées, vérification Ed25519 avec `cryptography`, `release.json` | WP-PACKAGING, WP-CORE | C3 |
| U2 | Assistant privilégié : `update_verify`, `update_start` (unité transitoire), `update_status`, `journal_errors`, sauvegarde d'état, `pelagos upgrade apply` | WP-INSTALLER, contrat (`cli.py`) | C3, U1 |
| U3 | Déroulé : machine d'état dans `updates.rollout`, tour de chaque nœud, contrôles d'après installation repris de `deploy-prod.sh`, retour automatique, sources (dépôt téléversé, GitHub), distribution des paquets entre nœuds | WP-COLLECTOR, WP-CORE | C3, U2 |
| U4 | Paquets des moteurs : déroulé `engine_packages` (BIND puis Kea sous maintenance HA), lien depuis `security_advisory` | WP-INSTALLER, WP-KEA, WP-BIND | U3 |
| U5 | API des mises à jour (`/admin/updates*`) | WP-API-AUTH | C3, U3 |
| U6 | Écran Mises à jour (disponible, aperçu, déroulé qui survit au redémarrage, paquets des moteurs, historique), mise à jour de `docs/user/upgrade.md` | WP-FRONTEND | C3 (factice), U5 |
| U7 | Démons et labo : déroulé sur deux collecteurs, `test_upgrade_ui_lab.py` (deb amd64 et arm64, paquet cassé et retour, BIND de la distribution), variante rpm | WP-LAB-E2E | U2 à U5 |
| C4 | Contrat de la 0.2.4 : jetons d'API (section 16 de l'architecture), route `/hosts/ipv6/plan` | contrat, WP-CORE | |
| V4 | Plans IPv6 : AAAA et PTR de la sélection, remplacement de préfixe, création de la zone inverse proposée | WP-API-AUTH, WP-BIND | C4, V2 |
| V5 | Sélection et plan dans l'onglet IPv6, partie IPv6 de la fiche d'hôte ; labo IPv6 (radvd, client SLAAC avec adresses temporaires) | WP-FRONTEND, WP-LAB-E2E | V4 |
| H1 | Jetons d'API : authentification `Bearer`, empreintes, réseaux, échéance, débit, verbes, API `/admin/api-tokens` | WP-API-AUTH | C4 |
| C5 | Contrat de la 0.3.0 : scope `kea.migration`, état `kea.migration` de `cluster.toml`, route `/repl/v1/kea/leases`, étapes de pair de l'assistant, réglages `kea.migration_*` | contrat, WP-CORE | K1 |
| K3 | Préparation de la migration : archive, téléchargement des paquets, configurations 3.x posées à côté, état noté (paquets et versions exactes) | WP-INSTALLER, WP-KEA | C5 |
| K4 | Temps 1 et retour du temps 1 : maintenance HA, installation ISC sur le standby, validation réelle des deux configurations, retour en 2.6 du standby | WP-INSTALLER, WP-KEA | K3 |
| K5 | Temps 2 et 3 : copie du fichier de baux par mTLS, démarrage en `partner-down` avec délais réduits, mesure de la coupure, retour automatique sur dépassement, primaire migré, délais remis ; retour de la paire entière | WP-INSTALLER, WP-KEA, WP-CORE | K4 |
| K6 | Assistant de migration (frise des temps, HA en direct, coupure mesurée, retour) | WP-FRONTEND | C5 (factice), K5 |
| K7 | Labo de la migration depuis la paire Kea 2.6.3 Debian (HA TLS, D2, client qui renouvelle), variante Rocky | WP-LAB-E2E | K3 à K5 |

Ordre et releases proposés (la 0.2.1 en cours garde les correctifs des points 64 et 65, sans fonction nouvelle) :

- **0.2.2** : C2 ; puis en parallèle R1, R2, K1, V1 ; puis R3, K2, V2 ; puis R4, V3, R5. Résolveur complet, analyse de migration Kea en lecture seule (utile tout de suite : elle dit ce qui casserait en production), contrôles IPv6.
- **0.2.3** : C3 ; U1 ; U2 ; U3 ; puis U4, U5 en parallèle ; U6 ; U7. Mise à jour depuis l'interface et paquets des moteurs. La 0.2.3 s'installe encore par `deploy-prod.sh` ; les suivantes peuvent passer par l'interface.
- **0.2.4** : C4 ; puis H1, V4 en parallèle ; V5. Propositions IPv6. H1 a été livré plus tôt par le point 70 ; H2 à H5 (Home Assistant) sont retirés (13.8).
- **0.3.0** : C5 ; K3 ; K4 ; K5 ; K6 et K7. Migration Kea 3.x. Le numéro mineur change parce que la release change la façon de faire tourner Kea en production (série ISC par défaut, paquets remplacés) ; la production passe en Kea 3.2 avec cette release, au moment choisi par l'utilisateur.

### 13.11 Points 59 à 63 : décisions

Décidé le 2026-10-28 : chaque défaut recommandé est retenu tel quel.

Action de l'utilisateur avant la 0.3.0 (point 61) : générer la clé Ed25519 de signature des releases et la garder hors du dépôt ; seule la clé publique entre dans le paquet. Sans elle, `make release` produit une release non signée, que l'interface installe seulement après l'avertissement et la confirmation supplémentaire (décision du 2026-10-30).

| Point | Question | Décision |
| --- | --- | --- |
| 59 | Source et série cible de Kea | ISC Cloudsmith `kea-3-2` (3.2.1 pour trixie amd64 et arm64) ; backports Debian 3.0 et ISC 3.0 proposés en second choix |
| 59 | Paire HA mixte 2.6 / 3.x pendant la bascule | Non (exclue par ISC) : fenêtre courte de moins d'une minute, fichier de baux copié, `partner-down` accéléré |
| 59 | Retour arrière automatique pendant la fenêtre | Oui, au-delà de 180 s ou sur un échec de contrôle ; manuel après la fin de la migration |
| 59 | `kea-ctrl-agent` et sockets de contrôle HTTP(S) | Arrêté et désactivé ; sockets Unix seulement, `https` avec `cert-required` proposé uniquement si un client externe est trouvé |
| 59 | Date de migration de la production | Après la 0.3.0 et sa répétition au labo, à une heure creuse choisie par l'utilisateur, bouton manuel |
| 59 | Jusqu'à quand garder Kea 2.6 en mode dégradé | Tant que Debian 13 est la stable qui le livre ; retrait annoncé au plus tôt un an après la 0.3.0 |
| 60 | Seuils par défaut | p95 800 ms / 1 600 ms, délais dépassés 10 % / 30 %, TLD en échec après 3 sondes, `Mismatch` 100 par fenêtre ; réglables, valeurs observées sur 7 jours affichées |
| 60 | Repli vers des forwarders automatique ou proposé | Proposé seulement, avec notification ; option automatique désactivée |
| 60 | Retour du repli | Automatique à l'échéance (24 h par défaut, fixée dans le plan confirmé), proposé dès 15 min de sondes saines |
| 60 | Forwarders proposés | Préréglage Quad9 avec filtrage et DNSSEC (`9.9.9.9`, `149.112.112.112`, `2620:fe::fe`, `2620:fe::9`), `forward first` ; Quad9 sans filtrage, Cloudflare et liste libre en option |
| 61 | Source des versions | Dépôt de release téléversé dans l'interface et releases GitHub (jeton en lecture seule) ; dépôt apt ou dnf de Pelagos plus tard |
| 61 | Signature des releases | Ed25519 sur `SHA256SUMS`, clé privée générée et gardée par l'utilisateur hors du dépôt, lue par `make release` quand elle existe. Changé le 2026-10-30 : une release non signée (ou signée par une clé inconnue) s'installe depuis l'interface avec un avertissement, une confirmation explicite en plus de la normale (case et version saisie) et l'audit `update.unsigned_accepted` ; `SHA256SUMS` toujours vérifié ; signature présente mais invalide toujours refusée |
| 61 | Retour arrière | Automatique sur le nœud en échec quand `state_schema` ne change pas ; sinon arrêt et procédure guidée |
| 61 | Paquets BIND et Kea de la distribution | Même écran, onglet « Paquets des moteurs », même déroulé, sans changement de série |
| 62 | Sources des adresses observées | Table des voisins des nœuds, active ; baux DHCPv6 si le module est actif (source OPNsense retirée en 0.2.3, point 71) |
| 62 | Exclusion des adresses temporaires | Proposition seulement pour EUI-64 ou adresse vue plus de 3 jours ; temporaires jamais proposées |
| 62 | Création automatique ou par plan | Toujours par plan choisi hôte par hôte ; pas d'automatique dans la première version |
| 63 | Intégration Home Assistant | Retirée le 2026-10-30 (trop spécifique) : ni état ni présence, ni MQTT, ni écran Intégrations. Restent le préréglage webhook (13.1) et les jetons d'API généraux (point 70) |
| 81 | Règle unique de confirmation des plans (I2) | Toute suppression d'un objet de configuration (zone, clé, ACL, sous-réseau, réseau partagé, réservation, classe, option, bail) ; changement de préfixe ou réduction de pool ; baux actifs perdus ; adresse réservée tenue par un autre client ; plan composite dont les parties d'un même moteur visent des nœuds différents. Une même modification envoyée aux deux nœuds d'une paire HA ne compte pas comme écriture multi-nœuds, sinon chaque réservation demanderait confirmation. Les suppressions d'enregistrements DNS restent sans confirmation (avertissement DDNS seulement). Raisons dans `requires_confirmation_reasons`, impact calculé une fois dans `services.plan_impact` (architecture section 6) |
| tous | Ordre des releases | 0.2.2 résolveur, analyse Kea, contrôles IPv6 ; 0.2.3 mises à jour ; 0.2.4 IPv6 (Home Assistant retiré) ; 0.3.0 migration Kea |
