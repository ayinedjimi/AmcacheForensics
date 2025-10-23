# 🚀 AmcacheForensics - Analyseur Forensique de l'Amcache Windows


**Auteur** : Ayi NEDJIMI
**Licence** : MIT
**Plateforme** : Windows (Win32 GUI)

## 📋 Description

AmcacheForensics est un outil forensique spécialisé dans l'analyse de **Amcache.hve**, une base de données du registre Windows qui enregistre les informations sur tous les exécutables lancés sur le système, y compris leurs hash SHA-1, chemins complets, métadonnées PE et timestamps de première exécution.


## Qu'est-ce que l'Amcache ?

L'Amcache (Application Compatibility Cache) est un artefact forensique essentiel :

### Caractéristiques
- **Emplacement** : `C:\Windows\AppCompat\Programs\Amcache.hve`
- **Type** : Fichier hive du registre (format binaire)
- **But** : Compatibilité applicative et Shimming
- **Valeur forensique** : Enregistre TOUS les exécutables lancés, même supprimés

### Informations stockées
- **SHA-1** : Hash unique de l'exécutable
- **Chemin complet** : Emplacement lors de la première exécution
- **Taille** : Taille du fichier en octets
- **Company Name** : Éditeur de l'application
- **Product Name** : Nom commercial du logiciel
- **File Version** : Version du fichier
- **Link Date** : Timestamp de compilation PE
- **First Run** : Date de première exécution (Windows 10+)
- **Last Modified** : Dernière modification du fichier


## ✨ Fonctionnalités principales

### Chargement de l'Amcache
- **Montage offline** : Utilisation de `RegLoadKey` pour monter le hive
- **Lecture sécurisée** : Aucune modification du fichier original
- **Démontage automatique** : Cleanup avec `RegUnloadKey`
- **Support multi-versions** : Compatible Windows 7, 8, 10, 11

### Parsing et extraction
- **Navigation hiérarchique** : Parse les clés `Root\File` et `Root\InventoryApplicationFile`
- **Extraction complète** : Toutes les métadonnées importantes
- **Détection de chemins suspects** : Identification automatique de paths malveillants
- **Tri chronologique** : Affichage par date de première exécution

### Recherche et filtrage
- **Recherche par SHA-1** : Identification rapide d'un hash connu
- **Recherche par chemin** : Filtrage par nom de fichier ou dossier
- **Détection automatique** : Signalement des chemins `Temp`, `Downloads`, etc.

### Export et reporting
- **Export CSV** : Format UTF-8 pour analyse externe
- **Compteurs** : Nombre total d'entrées trouvées
- **Logs détaillés** : Traçabilité complète des opérations


## Interface utilisateur

### Contrôles principaux
1. **Bouton "Charger Amcache.hve"** : Monte et parse l'Amcache
2. **Zone de recherche** : Champ texte pour SHA-1 ou chemin
3. **Bouton "Chercher"** : Applique le filtre de recherche
4. **Bouton "Exporter"** : Sauvegarde en CSV
5. **Barre de progression** : Indicateur du parsing
6. **ListView** : Résultats avec colonnes :
   - SHA1 (hash du fichier)
   - Chemin (path complet)
   - Taille (en octets/KB/MB)
   - Company (éditeur)
   - Product (nom commercial)
   - First Run (première exécution)
   - Notes (observations forensiques)
7. **Journal de log** : Messages et erreurs


## Compilation

### Prérequis
- Visual Studio 2019/2022 avec outils C++
- Windows SDK (10.0 ou supérieur)
- Support Unicode
- Privilèges administrateur pour l'exécution

### Compilation automatique
```batch
go.bat
```

### Compilation manuelle
```batch
cl.exe /nologo /W4 /EHsc /O2 /D_UNICODE /DUNICODE /FeAmcacheForensics.exe AmcacheForensics.cpp ^
    kernel32.lib user32.lib gdi32.lib comctl32.lib comdlg32.lib shlwapi.lib advapi32.lib
```


# 🚀 Clic droit > Exécuter en tant qu'administrateur

## 🚀 Utilisation

### Prérequis d'exécution
**CRITIQUE** : L'outil nécessite :
- Privilèges **Administrateur**
- Privilège **SeBackupPrivilege** (automatique pour les admins)

### Lancement
```batch
AmcacheForensics.exe
```

### Workflow basique
1. Lancez l'application en administrateur
2. Cliquez sur "Charger Amcache.hve"
3. Attendez le parsing (peut prendre 10-30 secondes)
4. Consultez les résultats
5. Utilisez la recherche pour trouver un SHA-1 ou un chemin spécifique
6. Exportez les résultats

### Workflow d'investigation
```
1. Malware détecté : SHA-1 = abc123...
2. Lancer AmcacheForensics en admin
3. Charger l'Amcache
4. Rechercher le SHA-1 : "abc123"
5. Identifier :
   - Chemin d'exécution : C:\Users\John\Downloads\
   - Première exécution : 2025-10-18 14:25:30
   - Company : (vide) <- suspect
   - Product : (vide) <- suspect
6. Noter dans le rapport forensique
7. Croiser avec Prefetch et USN Journal
```


## Architecture technique

### Structure de l'Amcache

#### Clés du registre (Windows 10+)
```
HKEY_LOCAL_MACHINE\AMCACHE_ANALYSIS\
├── Root\
│   ├── File\
│   │   ├── {Volume GUID}\
│   │   │   └── {File ID}\
│   │   │       ├── 0 = Product Name
│   │   │       ├── 1 = Company Name
│   │   │       ├── c = Size (QWORD)
│   │   │       ├── 11 = LinkDate (FILETIME)
│   │   │       ├── 15 = Full Path
│   │   │       └── 101 = SHA1
│   └── InventoryApplicationFile\
│       └── (structure similaire)
```

#### Valeurs importantes
- **0** : Product Name (REG_SZ)
- **1** : Company Name (REG_SZ)
- **c** : File Size (REG_QWORD)
- **11** : Link Date / First Run (REG_QWORD -> FILETIME)
- **15** : Full Path (REG_SZ)
- **101** : SHA1 (REG_SZ, hexadécimal)

### APIs Windows utilisées

#### Gestion du registre offline
```cpp
// Charger le hive
RegLoadKeyW(HKEY_LOCAL_MACHINE, L"AMCACHE_ANALYSIS", L"C:\\...\\Amcache.hve");

// Ouvrir la clé
RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"AMCACHE_ANALYSIS", ...);

// Énumérer les sous-clés
RegEnumKeyExW(hKey, index, ...);

// Lire les valeurs
RegQueryValueExW(hKey, valueName, ...);

// Décharger le hive
RegUnloadKeyW(HKEY_LOCAL_MACHINE, L"AMCACHE_ANALYSIS");
```

### Détection de chemins suspects

#### Patterns malveillants
```cpp
bool IsSuspiciousPath(const std::wstring& path) {
    // Chemins temporaires
    - \\Temp\\
    - \\Tmp\\
    - \\AppData\\Local\\Temp\\

    // Dossiers de téléchargement
    - \\Downloads\\

    // Dossiers partagés
    - \\Users\\Public\\
    - \\ProgramData\\

    return true si trouvé;
}
```


## 🚀 Cas d'usage forensiques

### 1. Identification de malware par SHA-1
```
IOC reçu : SHA1 = 5a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b
Question : Ce malware a-t-il été exécuté ?

Recherche dans Amcache :
- > TROUVÉ : malware.exe
   Chemin : C:\Users\Victim\Downloads\invoice.exe
   First Run : 2025-10-15 08:30:12
   Company : (vide) <- suspect
   Product : (vide) <- suspect

Conclusion : Malware confirmé, exécuté depuis Downloads
```

### 2. Reconstruction de timeline d'attaque
```
Timeline Amcache :
08:30 - WINRAR.EXE (extraction)
08:32 - SETUP.EXE (installation initiale)
08:35 - MALWARE.EXE (payload principal)
08:40 - PERSISTENCE.EXE (mécanisme de survie)

Corrélation avec Prefetch :
- Même timestamps confirmés
- Compteurs d'exécution cohérents
```

### 3. Détection d'exécution depuis USB
```
Amcache :
E:\tools\hacking_tool.exe
First Run : 2025-10-18 15:30:00

USBForensics :
USB Kingston 32GB connecté : 2025-10-18 15:29:45

Conclusion : Outil lancé depuis USB externe 15 secondes après connexion
```

### 4. Identification de logiciels non autorisés
```
Recherche : "torrent"
Résultats :
- C:\Program Files\uTorrent\utorrent.exe
- C:\Users\John\Desktop\BitTorrent.exe

Recherche : "crack"
Résultats :
- C:\Users\John\Downloads\keygen.exe
- C:\Temp\crack_tool.exe (SUSPECT)

Conclusion : Usage de logiciels interdits par la politique d'entreprise
```

### 5. Anti-forensics detection
```
Recherche : "ccleaner", "bleachbit", "eraser"
Résultats :
- CCleaner.exe : First Run 2025-10-18 16:00:00

Timeline :
16:00 - Attaque détectée
16:05 - CCleaner exécuté

Conclusion : Tentative d'effacement de traces après l'attaque
```


## Valeur forensique de l'Amcache

### Avantages par rapport au Prefetch
- **Historique complet** : Ne se limite pas à 1024 fichiers
- **SHA-1 disponible** : Identification unique même si fichier supprimé
- **Métadonnées PE** : Company, Product, Version
- **Résistant à la suppression** : Moins connu des attaquants

### Avantages par rapport au USN Journal
- **Preuve d'exécution** : Le fichier a été LANCÉ, pas seulement créé
- **Hash intégré** : Identification sans avoir le fichier
- **Métadonnées enrichies** : Informations PE

### Complémentarité avec autres artefacts
```
Amcache     : Preuve qu'un exe a été lancé + SHA1
Prefetch    : Timestamps multiples + compteur d'exécutions
USN Journal : Opérations fichier (création, modification, suppression)
Event Logs  : Context système (Process Creation, Logon, etc.)

- > Timeline forensique complète
```


## Limitations connues

### Limitations système
- **Privilèges requis** : Admin + SeBackupPrivilege
- **Fichier verrouillé** : Amcache.hve peut être en cours d'utilisation
- **Rotation** : Anciennes entrées peuvent être supprimées (rare)

### Limitations de l'outil
- **Parsing simplifié** : Certaines valeurs optionnelles peuvent être manquées
- **Pas de hash MD5** : Seul SHA-1 disponible (limitation Windows)
- **Chemins incomplets** : Certaines versions peuvent avoir des chemins tronqués
- **Timestamps approximatifs** : LinkDate ≠ toujours First Run exact

### Limitations forensiques
- **Suppression possible** : Un attaquant peut supprimer Amcache.hve
- **Manipulation possible** : Modification offline du hive possible
- **Exécutions depuis réseau** : Pas toujours enregistrées
- **Collisions SHA-1** : Théoriquement possibles (très rare)


## Amélioration futures

### Court terme
- **Export JSON/XML** : Formats additionnels
- **Filtres avancés** : Par date, taille, company
- **Copie vers clipboard** : SHA-1 et chemins
- **Highlight suspects** : Coloration des entrées suspectes

### Moyen terme
- **Intégration VirusTotal** : Scan automatique des SHA-1
- **Base de données IOC** : Comparaison avec threat intel
- **Corrélation automatique** : Lien avec Prefetch/USN Journal
- **Timeline graphique** : Visualisation temporelle

### Long terme
- **Analyse différentielle** : Comparaison de deux Amcache
- **Machine learning** : Détection automatique de malware
- **Mode réseau** : Analyse de multiples systèmes
- **API REST** : Intégration SIEM/SOAR


# 🚀 Charger le hive (admin requis)

# 🚀 Lister les entrées

# 🚀 Décharger

## Outils complémentaires

### Outils Microsoft
```batch
REM Voir les clés d'un hive offline
reg.exe load HKLM\TEMP C:\Windows\AppCompat\Programs\Amcache.hve
reg.exe query HKLM\TEMP\Root\File
reg.exe unload HKLM\TEMP
```

### PowerShell
```powershell
reg load HKLM\AMC C:\Windows\AppCompat\Programs\Amcache.hve

Get-ChildItem HKLM:\AMC\Root\File -Recurse

reg unload HKLM\AMC
```

### Outils forensiques
- **AmcacheParser (Eric Zimmerman)** : Outil en ligne de commande référence
- **Registry Explorer** : Visualiseur graphique de hives
- **Autopsy** : Suite forensique avec module Amcache
- **KAPE** : Collecteur d'artefacts incluant Amcache


## Références techniques

### Documentation communautaire
- **SANS DFIR** : "Amcache Forensics"
- **13Cubed (YouTube)** : "Amcache Analysis"
- **Mandiant** : "Leveraging the Application Compatibility Cache"

### Recherches
- "Windows 10 Amcache Analysis" - SANS (2016)
- "Forensic Analysis of Amcache.hve" - DFIR Review (2020)
- Eric Zimmerman's Blog : "Amcache Deep Dive"

### Outils de référence
- AmcacheParser : https://github.com/EricZimmerman/AmcacheParser
- RegRipper plugin : rip.pl -r Amcache.hve -p amcache


## Corrélation avec autres artefacts

### Amcache + Prefetch + USN Journal
```
Timeline complète :
14:20 - USN : malware.exe créé (FILE_CREATE)
14:25 - Amcache : malware.exe first run (Company: vide)
14:25 - Prefetch : MALWARE.EXE-12345678.pf créé (run count: 1)
14:30 - USN : malware.exe supprimé (FILE_DELETE)
14:30 - Prefetch : MALWARE.EXE (run count: 1) <- preuve persistence
14:30 - Amcache : SHA1 = abc123... <- identification

Conclusion : Malware exécuté puis supprimé, mais SHA1 conservé dans Amcache
```

### Amcache + SRUM (System Resource Usage Monitor)
```
SRUM : Processus malware.exe - utilisation réseau 500 MB
Amcache : malware.exe - SHA1 abc123... - Path C:\Temp\

Conclusion : Exfiltration de données confirmée
```


## Format d'export CSV

```csv
SHA1,Chemin,Taille,CompanyName,ProductName,FirstRun,Notes
"5a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b","C:\Users\John\Downloads\malware.exe",245760,"","","2025-10-18 14:25:30","Chemin suspect (temp/downloads)"
"abc123def456...","C:\Program Files\Microsoft Office\WINWORD.EXE",52428800,"Microsoft Corporation","Microsoft Word","2025-09-01 10:00:00",""
```

**Encodage** : UTF-8 avec BOM
**Séparateur** : Virgule
**Format** : Standard CSV (Excel/LibreOffice compatible)


## 🔧 Dépannage

### Erreur "Impossible de charger l'Amcache"
**Cause** : Manque de privilèges ou fichier verrouillé
**Solution** : Exécutez en admin et fermez les processus accédant à Amcache.hve

### Fichier Amcache.hve introuvable
**Cause** : Chemin incorrect ou OS non supporté
**Solution** : Vérifiez `C:\Windows\AppCompat\Programs\Amcache.hve`

### Peu d'entrées trouvées
**Cause** : Parsing incomplet ou version OS ancienne
**Solution** : Normal sur systèmes récemment installés

### Erreur SeBackupPrivilege
**Cause** : Compte utilisateur sans privilèges suffisants
**Solution** : Utilisez un compte Administrateur local


## 🔒 Sécurité et éthique

### Usage légal
- Utilisez uniquement sur des systèmes autorisés
- Respectez les lois sur la protection des données
- Documentez toutes les investigations
- Ne partagez jamais de SHA-1 de fichiers confidentiels

### Protection des preuves
- Travaillez sur des copies d'Amcache.hve
- Calculez les hash du fichier avant manipulation
- Documentez toute opération
- Conservez les logs d'analyse

### Chain of custody
- Horodatez le moment de collecte
- Documentez la source du fichier
- Signez numériquement les exports
- Conservez les preuves en écriture seule


## 📄 Licence MIT

```
Copyright (c) 2025 Ayi NEDJIMI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

[Texte complet de la licence MIT]
```


## Support

### Ressources
- Documentation complète (ce README)
- Code source commenté
- Exemples de workflows

### Outils de la suite
- **NTFSJournalParser** : Timeline USN Journal
- **PrefetchAnalyzer** : Historique d'exécution
- **RecycleBinForensics** : Fichiers supprimés
- **AlternateDataStreamScanner** : ADS cachés

**Contact** : Ayi NEDJIMI

- --

**AmcacheForensics** - Outil forensique professionnel pour l'analyse de l'Amcache Windows
Développé par **Ayi NEDJIMI** - 2025


---

<div align="center">

**⭐ Si ce projet vous plaît, n'oubliez pas de lui donner une étoile ! ⭐**

</div>