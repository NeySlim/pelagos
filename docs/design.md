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

## 13. Sixième passe : notifications, sauvegardes, DDNS sans point unique de panne

Trois fonctions de priorité 1, spécifiées ici avant tout code (points 56, 57 et 58 du relevé de production), puis les fonctions 59 à 63 sous forme de questions ouvertes. Les contrats techniques (schémas, routes exactes, champs) iront dans `docs/architecture.md` par le premier lot de chaque fonction, avec une entrée dans `docs/contracts-changes.md` ; ce chapitre fixe le besoin, les écrans, les décisions et le découpage.

Règles communes aux trois :

- Une modification d'un moteur (BIND, Kea, D2) passe par un plan : aperçu, validations, confirmation, application nœud par nœud, retour arrière (architecture, sections 6 et 7). Un réglage propre à Pelagos (`cluster.toml`) suit le modèle des réglages existants : écrit par `update_cluster`, répliqué, audité avec l'état d'avant, donc réversible, sans plan.
- Nouveaux domaines de réglages : `notifications`, `archives`, `ddns` (ajoutés à `DOMAINS` du registre, nommage de la section 10 de l'architecture). Les seuils qui lèvent une alerte vont dans `[settings.checks]`. Les entrées écrites par un écran dédié (canaux, destinations, rôles DNS) sont refusées par `PUT /admin/settings`, comme celles du RPZ.
- Secrets dans `cluster.toml [secrets]`, chiffrés par la clé maître, jamais renvoyés par l'API (booléens « défini »), masqués dans les plans, l'audit et les journaux.
- Chaque nouvelle alerte a sa clé de message (`alert.*`) en anglais et en français, et figure dans la table des alertes de la section 15 de l'architecture.
- Tests : les trois niveaux d'AGENTS.md. Le niveau unitaire n'ouvre aucun réseau : les transports sont injectés et remplacés par des faux en mémoire.

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
| Matrix | `PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}`, `msgtype` `m.text`, `format` `org.matrix.custom.html` ([spec Matrix v1.11](https://spec.matrix.org/v1.11/client-server-api/)) | `Authorization: Bearer` d'un compte robot | `txnId` = identifiant du lot : un renvoi est idempotent côté serveur |
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
- Clé de l'archive : Pelagos génère une identité X25519 à la mise en place ; la clé publique (`age1...`) est dans `cluster.toml`, l'identité privée dans `[secrets]` (`archives/identity`), chiffrée par la clé maître, pour que n'importe quel nœud puisse restaurer. Elle est proposée au téléchargement une fois, avec l'avertissement « sans elle, la perte de tout le cluster est irrécupérable ». Variante : l'administrateur fournit sa propre clé publique et Pelagos ne garde aucune identité ; la restauration demande alors de déposer l'identité. L'archive contient `master.key` et `ca.key` : elle n'est donc jamais stockée en clair, nulle part.

**Destinations**

| Destination | Mécanisme | Remarques |
| --- | --- | --- |
| Local | `/var/lib/pelagos/archives/local/`, les `local_keep_count` dernières | Toujours active ; sert de tampon si la destination distante échoue |
| Autre nœud du cluster | `POST /repl/v1/archives` en mTLS, rangée chez le pair dans `/var/lib/pelagos/archives/peers/<nœud d'origine>/` | Défaut dès qu'il y a deux nœuds ; couvre la perte d'un nœud, pas celle du site |
| Dossier monté | un chemin local que l'administrateur monte lui-même (NFS, SMB/CIFS par fstab ou automount systemd) | Pelagos ne monte rien et ne garde aucun mot de passe SMB ; il vérifie que le chemin est un point de montage et inscriptible |
| SFTP | client OpenSSH (`sftp -b`), clé privée dédiée stockée en secret, empreinte de la clé d'hôte épinglée | Pas de dépendance Python nouvelle |
| S3 compatible | question ouverte (ci-dessous) | |

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
| `GET /admin/archives` | `admin:archives` | | `{"settings","recipient","identity": {"stored"},"destinations","nodes": [{"node_id","last_success","last_error","next_run","running","complete"}]}` |
| `POST`, `PUT`, `DELETE /admin/archives/destinations[/{id}]` | `admin:archives` | destination, `secrets` | destination / `204` |
| `POST /admin/archives/destinations/test` | `admin:archives` | `{"destination_id"}` ou une destination non enregistrée | `{"ok","node_id","error"?}` |
| `POST /admin/archives/run` | `admin:archives` | `{"node_ids"?}` | `202 Job` |
| `GET /admin/archives/list?node_id=&destination_id=&page=&per_page=` | `admin:archives` | | paginé `{"id","node_id","created_at","size","sha256","destinations","complete","versions","verified_at"}` |
| `GET /admin/archives/{id}/download` | `admin:archives` | | flux `application/octet-stream` (fichier chiffré), audité |
| `POST /admin/archives/upload` | `admin:archives` | multipart : archive venue d'ailleurs | l'archive inscrite |
| `POST /admin/archives/{id}/inspect` | `admin:archives` | `{"identity"?}` | `{"manifest","parts": [{"id","engine","node_id","files","diff_summary"}]}` |
| `POST /admin/archives/{id}/restore/plan` | `admin:archives` plus l'écriture de chaque partie | `{"target_node_id","parts": [...],"identity"?,"include_user_files"?}` | `Plan` (scope `restore`, `requires_confirmation`), appliqué par `POST /plans/{id}/apply` en `202 Job` |
| `POST /admin/archives/identity` | `admin:archives` | `{"op": "generate"|"rotate"|"import","recipient"?}` | `{"recipient","identity_pem"?}` (une seule fois) |

Réplication : `POST /repl/v1/archives` (dépôt, taille bornée par `max_archive_mb`), `GET /repl/v1/archives?origin=` (liste), `GET /repl/v1/archives/<id>` (lecture). Nouvelle permission `admin:archives`. Nouveau scope de plan `restore`. Audit : `admin.archive.*`, `archive.create`, `archive.restore.apply|rollback`.

**Réglages**

`[settings.archives]` : `schedule_enabled` (faux tant qu'aucune clé n'existe), `start_time` (`"03:15"`), `interval_hours` (24), `stagger_minutes` (15), `keep_daily_count` (7), `keep_weekly_count` (4), `keep_monthly_count` (6), `local_keep_count` (3), `include_leases_enabled` (vrai), `verify_enabled` (vrai), `test_restore_days` (7, 0 = jamais), `max_archive_mb` (512). Écrits par l'écran : `archives.destinations`, `archives.recipient`. Secrets : `archives/identity`, `archives/dest/<id>/<ssh_key|access_key|secret_key>`. Seuils dans `[settings.checks]` : `archive_stale_factor` (2 : alerte quand la dernière archive réussie a plus de 2 intervalles), `archive_failures_critical_count` (3).

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
7. Rattrapage (plan « Rejouer le DDNS ») : fenêtre = début et fin de la panne (premier `update-timeout` ou `peer_offline` du primaire, jusqu'à la bascule ou au retour). Pelagos liste les baux actifs dont `cltt` tombe dans la fenêtre, qui ont un nom et un drapeau fqdn, et dont l'A, l'AAAA ou le PTR manque ou diffère (même jointure que les incohérences `lease_without_record`) ; le plan envoie `lease4-resend-ddns` / `lease6-resend-ddns` pour chacun sur un nœud dont Kea sert, par lots. Les noms dont le bail a disparu pendant la panne sont déjà levés par `record_without_lease` et les PTR orphelins, avec leurs plans existants. Un renvoi sur un nom déjà juste est sans effet (résolution de conflit par DHCID).
8. Automatisme : la bascule reste manuelle par défaut, avec notification (13.1) dès que l'alerte s'ouvre ; `failover_auto_enabled` permet de la faire seule après `failover_after_seconds` d'indisponibilité vue par tous les autres nœuds. Le rattrapage automatique (`replay_auto_enabled`) est désactivé par défaut et borné par `replay_max_leases`.

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

`[settings.ddns]` : `failover_auto_enabled` (faux), `failover_after_seconds` (300), `demote_on_return_enabled` (vrai), `replay_auto_enabled` (faux), `replay_max_leases` (2000), `replay_window_max_hours` (72). Écrit par l'écran : `ddns.roles`. Pas de secret nouveau : les clés existent déjà.

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

### 13.4 Fonctions suivantes (points 59 à 63) : questions ouvertes

Rien n'est décidé ici ; chaque point sera spécifié comme ci-dessus avant d'être codé.

- **59, assistant de migration Kea 2.6 vers 3.x** : une paire HA 2.6 / 3.x mixte est-elle prise en charge par ISC le temps de la bascule, ou faut-il une fenêtre courte ? Paquets ISC (Cloudsmith) sur Debian et Rocky, ou distribution quand elle passera en 3.x ? Que faire des hooks chargés et de `kea-ctrl-agent` (supprimé en 3.1.8) : conversion automatique en `control-sockets` HTTP/TLS ou seulement sockets Unix ? Retour arrière en 2.6 avec les baux écrits par 3.x : possible ?
- **60, surveillance du résolveur** : quels seuils par défaut (SERVFAIL, échecs DNSSEC, latence) sans données de référence ? Bascule temporaire vers des forwarders : automatique ou seulement proposée ? Quels forwarders proposer, et faut-il un retour automatique ?
- **61, mise à jour depuis l'interface** : source des versions (dépôt apt/dnf de Pelagos, release GitHub) et vérification des signatures ; qui exécute la mise à jour du paquet (l'assistant privilégié) et comment l'interface survit au redémarrage de son propre service ; retour arrière vers la version précédente quand le schéma de `cluster.toml` a changé ? Mises à jour BIND et Kea de la distribution dans le même écran ou à part ?
- **62, IPv6 AAAA et PTR** : source des adresses observées (table des voisins d'un routeur par API, OPNsense en premier ? journaux ? DHCPv6 seulement ?) ; règle d'exclusion des adresses temporaires de confidentialité ; création automatique ou toujours par plan choisi hôte par hôte ?
- **63, Home Assistant** : webhook seul (livré par 13.1), API en lecture avec jeton dédié, ou MQTT discovery (et alors quel courtier, avec quelle authentification) ? Quels capteurs en premier ? Présence d'un appareil par ses baux : quel délai pour « absent » ?

### 13.5 Lots d'implémentation

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
| B3 | Destinations : pair (`/repl/v1/archives`), dossier monté, SFTP ; S3 selon la réponse à la question ouverte | WP-CORE, WP-COLLECTOR | B1 |
| B4 | Restauration en ligne : inspection, diff par partie, plan composite `restore` (fichiers gérés, zones par UPDATE ou remplacement, Kea et D2, sections de `cluster.toml`, fusion de l'audit) | WP-API-AUTH, WP-BIND, WP-KEA | B1, B2 |
| B5 | Reconstruction : `pelagos restore` et `pelagos backup` en ligne de commande, documentation d'exploitation | contrat (`cli.py`), WP-INSTALLER | B1, B4 |
| B6 | API et écran Sauvegardes | WP-API-AUTH, WP-FRONTEND | B2 à B4 |
| B7 | Démons et labo : SFTP sur la VM Docker du labo, reconstruction de ns2 | WP-LAB-E2E | B2 à B5 |

Ordre proposé : C1 ; puis en parallèle N1, N2, D1, B1 ; puis N3, N4, D2, B2, B3 ; puis N5 (release 0.2.0 : notifications et rattrapage DDNS) ; D3, D4, D5, D6 (0.2.1 : reprise DDNS) ; B4, B5, B6, B7 (0.2.2 : sauvegardes). Les notifications passent d'abord parce que la bascule DDNS et les sauvegardes s'appuient sur elles pour prévenir.

**Questions ouvertes pour ces trois fonctions** (choix de l'utilisateur)

- [ ] Canaux de la première version : e-mail, ntfy, Gotify, webhook et Home Assistant, avec Matrix dans le même lot ou plus tard ?
- [ ] Sauvegardes vers S3 : nécessaires dès la première version ? Si oui, dépendance `boto3` (lourde) ou client S3 minimal écrit à la main (signature v4, PUT, GET, LIST) ?
- [ ] Clé des archives : identité gardée par le cluster (chiffrée par la clé maître) et téléchargée une fois, ou clé publique de l'administrateur seulement, sans identité sur les nœuds ?
- [ ] Bascule DDNS : manuelle par défaut avec notification, ou automatique après 5 minutes ?
- [ ] Rétrogradation automatique de l'ancien primaire à son retour : d'accord pour l'activer par défaut ?
- [ ] Rattrapage DDNS automatique après une panne, ou toujours par plan confirmé ?
- [ ] Les zones de production déclarées dans les fichiers de l'utilisateur doivent d'abord être confiées à Pelagos (point 33) pour être préparées : d'accord ?
- [ ] Baux Kea dans les archives par défaut (utile pour un nœud seul, redondant avec la HA) ?
