/*******************************************************************************
 * AmcacheForensics - Analyseur forensique de l'Amcache Windows
 *
 * Auteur  : Ayi NEDJIMI
 * Licence : MIT
 * Description : Parse Amcache.hve (Application Compatibility cache) pour extraire
 *               SHA1, chemins, timestamps et métadonnées des exécutables.
 ******************************************************************************/

#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <memory>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")

#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' "\
                        "version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

// Contrôles
#define IDC_BTN_LOAD         1001
#define IDC_LISTVIEW         1002
#define IDC_BTN_SEARCH       1003
#define IDC_BTN_EXPORT       1004
#define IDC_EDIT_LOG         1005
#define IDC_PROGRESS         1006
#define IDC_LABEL_STATUS     1007
#define IDC_EDIT_SEARCH      1008

// Structures
struct AmcacheEntry {
    std::wstring sha1;
    std::wstring path;
    LONGLONG size;
    std::wstring companyName;
    std::wstring productName;
    FILETIME firstRun;
    std::wstring notes;
};

// RAII
class HKeyGuard {
    HKEY hKey;
public:
    explicit HKeyGuard(HKEY key) : hKey(key) {}
    ~HKeyGuard() { if (hKey) RegCloseKey(hKey); }
    HKEY get() const { return hKey; }
    operator bool() const { return hKey != nullptr; }
};

// Globals
HWND g_hMainWnd = nullptr;
HWND g_hListView = nullptr;
HWND g_hLog = nullptr;
HWND g_hProgress = nullptr;
HWND g_hStatus = nullptr;
HWND g_hEditSearch = nullptr;
std::vector<AmcacheEntry> g_entries;
std::vector<AmcacheEntry> g_filteredEntries;
bool g_loading = false;
HKEY g_hLoadedHive = nullptr;

void Log(const std::wstring& msg) {
    if (!g_hLog) return;
    int len = GetWindowTextLengthW(g_hLog);
    SendMessageW(g_hLog, EM_SETSEL, len, len);
    SendMessageW(g_hLog, EM_REPLACESEL, FALSE, (LPARAM)(msg + L"\r\n").c_str());
}

std::wstring FileTimeToString(const FILETIME& ft) {
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) return L"N/A";

    SYSTEMTIME st;
    if (!FileTimeToSystemTime(&ft, &st)) return L"N/A";

    wchar_t buf[64];
    swprintf_s(buf, L"%04d-%02d-%02d %02d:%02d:%02d",
               st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

std::wstring FormatSize(LONGLONG size) {
    if (size < 1024) return std::to_wstring(size) + L" B";
    if (size < 1024 * 1024) return std::to_wstring(size / 1024) + L" KB";
    if (size < 1024 * 1024 * 1024) return std::to_wstring(size / (1024 * 1024)) + L" MB";
    return std::to_wstring(size / (1024 * 1024 * 1024)) + L" GB";
}

bool IsSuspiciousPath(const std::wstring& path) {
    std::wstring lowerPath = path;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

    // Suspicious paths
    return (lowerPath.find(L"\\temp\\") != std::wstring::npos ||
            lowerPath.find(L"\\tmp\\") != std::wstring::npos ||
            lowerPath.find(L"\\downloads\\") != std::wstring::npos ||
            lowerPath.find(L"\\appdata\\local\\temp\\") != std::wstring::npos ||
            lowerPath.find(L"\\users\\public\\") != std::wstring::npos ||
            lowerPath.find(L"\\programdata\\") != std::wstring::npos);
}

std::wstring ReadRegString(HKEY hKey, const wchar_t* valueName) {
    wchar_t buffer[2048] = {};
    DWORD bufferSize = sizeof(buffer);
    DWORD type = 0;

    if (RegQueryValueExW(hKey, valueName, nullptr, &type,
                        reinterpret_cast<BYTE*>(buffer), &bufferSize) == ERROR_SUCCESS) {
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            return buffer;
        }
    }

    return L"";
}

LONGLONG ReadRegQWORD(HKEY hKey, const wchar_t* valueName) {
    LONGLONG value = 0;
    DWORD bufferSize = sizeof(value);
    DWORD type = 0;

    if (RegQueryValueExW(hKey, valueName, nullptr, &type,
                        reinterpret_cast<BYTE*>(&value), &bufferSize) == ERROR_SUCCESS) {
        if (type == REG_QWORD) {
            return value;
        }
    }

    return 0;
}

FILETIME ReadRegFileTime(HKEY hKey, const wchar_t* valueName) {
    FILETIME ft = {};
    LONGLONG value = ReadRegQWORD(hKey, valueName);

    if (value > 0) {
        ft.dwLowDateTime = static_cast<DWORD>(value & 0xFFFFFFFF);
        ft.dwHighDateTime = static_cast<DWORD>((value >> 32) & 0xFFFFFFFF);
    }

    return ft;
}

void ParseAmcacheKey(HKEY hRootKey, const std::wstring& subKeyPath, int& count) {
    HKEY hSubKey = nullptr;

    if (RegOpenKeyExW(hRootKey, subKeyPath.c_str(), 0, KEY_READ, &hSubKey) != ERROR_SUCCESS)
        return;

    HKeyGuard guard(hSubKey);

    // Enumerate subkeys (file entries)
    DWORD index = 0;
    wchar_t keyName[256];

    while (true) {
        DWORD keyNameSize = 256;
        if (RegEnumKeyExW(hSubKey, index++, keyName, &keyNameSize,
                         nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
            break;

        // Open file entry key
        HKEY hFileKey = nullptr;
        if (RegOpenKeyExW(hSubKey, keyName, 0, KEY_READ, &hFileKey) != ERROR_SUCCESS)
            continue;

        HKeyGuard fileGuard(hFileKey);

        AmcacheEntry entry = {};

        // Read values
        entry.sha1 = ReadRegString(hFileKey, L"101"); // SHA1
        if (entry.sha1.empty()) {
            entry.sha1 = ReadRegString(hFileKey, L"SHA1");
        }

        entry.path = ReadRegString(hFileKey, L"15"); // Full path
        if (entry.path.empty()) {
            entry.path = ReadRegString(hFileKey, L"FullPath");
        }

        entry.size = ReadRegQWORD(hFileKey, L"c"); // Size
        if (entry.size == 0) {
            entry.size = ReadRegQWORD(hFileKey, L"Size");
        }

        entry.companyName = ReadRegString(hFileKey, L"1"); // Company
        if (entry.companyName.empty()) {
            entry.companyName = ReadRegString(hFileKey, L"Company");
        }

        entry.productName = ReadRegString(hFileKey, L"0"); // Product
        if (entry.productName.empty()) {
            entry.productName = ReadRegString(hFileKey, L"Product");
        }

        entry.firstRun = ReadRegFileTime(hFileKey, L"11"); // LinkDate or first run
        if (entry.firstRun.dwLowDateTime == 0) {
            entry.firstRun = ReadRegFileTime(hFileKey, L"LinkDate");
        }

        // Check if suspicious
        if (IsSuspiciousPath(entry.path)) {
            entry.notes = L"Chemin suspect (temp/downloads)";
        }

        // Add to list if has useful data
        if (!entry.sha1.empty() || !entry.path.empty()) {
            g_entries.push_back(entry);
            count++;

            if (count % 100 == 0) {
                SendMessageW(g_hProgress, PBM_SETPOS, (count / 10) % 100, 0);
            }
        }
    }
}

void UpdateListView(const std::vector<AmcacheEntry>& entries) {
    if (!g_hListView) return;

    SendMessageW(g_hListView, WM_SETREDRAW, FALSE, 0);
    ListView_DeleteAllItems(g_hListView);

    int idx = 0;
    for (const auto& entry : entries) {
        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = idx++;

        // SHA1
        lvi.pszText = const_cast<LPWSTR>(entry.sha1.c_str());
        ListView_InsertItem(g_hListView, &lvi);

        // Path
        ListView_SetItemText(g_hListView, lvi.iItem, 1, const_cast<LPWSTR>(entry.path.c_str()));

        // Size
        std::wstring sizeStr = FormatSize(entry.size);
        ListView_SetItemText(g_hListView, lvi.iItem, 2, const_cast<LPWSTR>(sizeStr.c_str()));

        // Company
        ListView_SetItemText(g_hListView, lvi.iItem, 3, const_cast<LPWSTR>(entry.companyName.c_str()));

        // Product
        ListView_SetItemText(g_hListView, lvi.iItem, 4, const_cast<LPWSTR>(entry.productName.c_str()));

        // First Run
        std::wstring firstRunStr = FileTimeToString(entry.firstRun);
        ListView_SetItemText(g_hListView, lvi.iItem, 5, const_cast<LPWSTR>(firstRunStr.c_str()));

        // Notes
        ListView_SetItemText(g_hListView, lvi.iItem, 6, const_cast<LPWSTR>(entry.notes.c_str()));
    }

    SendMessageW(g_hListView, WM_SETREDRAW, TRUE, 0);
    InvalidateRect(g_hListView, nullptr, TRUE);

    std::wstring status = L"Entrées affichées : " + std::to_wstring(entries.size());
    SetWindowTextW(g_hStatus, status.c_str());
}

DWORD WINAPI LoadThread(LPVOID) {
    g_entries.clear();
    g_filteredEntries.clear();

    wchar_t amcachePath[MAX_PATH];
    ExpandEnvironmentStringsW(L"%SystemRoot%\\AppCompat\\Programs\\Amcache.hve",
                             amcachePath, MAX_PATH);

    Log(L"[INFO] Chargement de l'Amcache : " + std::wstring(amcachePath));

    // Check if file exists
    if (GetFileAttributesW(amcachePath) == INVALID_FILE_ATTRIBUTES) {
        Log(L"[ERREUR] Fichier Amcache.hve introuvable");
        g_loading = false;
        EnableWindow(GetDlgItem(g_hMainWnd, IDC_BTN_LOAD), TRUE);
        return 1;
    }

    // Load hive
    LONG result = RegLoadKeyW(HKEY_LOCAL_MACHINE, L"AMCACHE_ANALYSIS", amcachePath);

    if (result != ERROR_SUCCESS) {
        Log(L"[ERREUR] Impossible de charger l'Amcache (Erreur: " +
            std::to_wstring(result) + L")");
        Log(L"[INFO] Exécutez en tant qu'administrateur avec privilège SeBackupPrivilege");
        g_loading = false;
        EnableWindow(GetDlgItem(g_hMainWnd, IDC_BTN_LOAD), TRUE);
        return 1;
    }

    Log(L"[SUCCÈS] Amcache chargé, parsing en cours...");

    // Open loaded hive
    HKEY hAmcache = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"AMCACHE_ANALYSIS", 0,
                     KEY_READ, &hAmcache) != ERROR_SUCCESS) {
        Log(L"[ERREUR] Impossible d'ouvrir la clé Amcache");
        RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"AMCACHE_ANALYSIS");
        g_loading = false;
        EnableWindow(GetDlgItem(g_hMainWnd, IDC_BTN_LOAD), TRUE);
        return 1;
    }

    HKeyGuard hiveGuard(hAmcache);
    g_hLoadedHive = hAmcache;

    int count = 0;

    // Try different paths (Amcache structure varies by Windows version)
    ParseAmcacheKey(hAmcache, L"Root\\File", count);
    ParseAmcacheKey(hAmcache, L"Root\\InventoryApplicationFile", count);

    Log(L"[SUCCÈS] Parsing terminé : " + std::to_wstring(count) + L" entrées");

    // Sort by first run (most recent first)
    std::sort(g_entries.begin(), g_entries.end(),
              [](const AmcacheEntry& a, const AmcacheEntry& b) {
                  return CompareFileTime(&a.firstRun, &b.firstRun) > 0;
              });

    UpdateListView(g_entries);

    // Unload hive
    g_hLoadedHive = nullptr;
    RegCloseKey(hAmcache);
    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"AMCACHE_ANALYSIS");

    Log(L"[INFO] Amcache déchargé");

    g_loading = false;
    EnableWindow(GetDlgItem(g_hMainWnd, IDC_BTN_LOAD), TRUE);
    SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);

    return 0;
}

void OnLoad() {
    if (g_loading) {
        MessageBoxW(g_hMainWnd, L"Chargement déjà en cours...", L"Info", MB_OK | MB_ICONINFORMATION);
        return;
    }

    g_loading = true;
    EnableWindow(GetDlgItem(g_hMainWnd, IDC_BTN_LOAD), FALSE);

    CreateThread(nullptr, 0, LoadThread, nullptr, 0, nullptr);
}

void OnSearch() {
    wchar_t searchText[256] = {};
    GetWindowTextW(g_hEditSearch, searchText, 256);

    if (wcslen(searchText) == 0) {
        UpdateListView(g_entries);
        return;
    }

    std::wstring search = searchText;
    std::transform(search.begin(), search.end(), search.begin(), ::towlower);

    g_filteredEntries.clear();

    for (const auto& entry : g_entries) {
        std::wstring lowerSha1 = entry.sha1;
        std::wstring lowerPath = entry.path;
        std::transform(lowerSha1.begin(), lowerSha1.end(), lowerSha1.begin(), ::towlower);
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

        if (lowerSha1.find(search) != std::wstring::npos ||
            lowerPath.find(search) != std::wstring::npos) {
            g_filteredEntries.push_back(entry);
        }
    }

    UpdateListView(g_filteredEntries);
    Log(L"[INFO] Recherche : " + std::to_wstring(g_filteredEntries.size()) + L" résultats");
}

void OnExport() {
    if (g_entries.empty()) {
        MessageBoxW(g_hMainWnd, L"Aucune donnée à exporter.", L"Info", MB_OK | MB_ICONINFORMATION);
        return;
    }

    OPENFILENAMEW ofn = {};
    wchar_t fileName[MAX_PATH] = L"amcache_forensics.csv";

    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hMainWnd;
    ofn.lpstrFilter = L"CSV Files (*.csv)\0*.csv\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT;

    if (!GetSaveFileNameW(&ofn)) return;

    std::wofstream ofs(fileName);
    if (!ofs) {
        MessageBoxW(g_hMainWnd, L"Impossible de créer le fichier.", L"Erreur", MB_OK | MB_ICONERROR);
        return;
    }

    ofs.imbue(std::locale(""));

    ofs << L"SHA1,Chemin,Taille,CompanyName,ProductName,FirstRun,Notes\n";

    for (const auto& entry : g_entries) {
        ofs << L"\"" << entry.sha1 << L"\","
            << L"\"" << entry.path << L"\","
            << entry.size << L","
            << L"\"" << entry.companyName << L"\","
            << L"\"" << entry.productName << L"\","
            << L"\"" << FileTimeToString(entry.firstRun) << L"\","
            << L"\"" << entry.notes << L"\"\n";
    }

    ofs.close();
    Log(L"[SUCCÈS] Données exportées : " + std::wstring(fileName));
    MessageBoxW(g_hMainWnd, L"Données exportées avec succès.", L"Succès", MB_OK | MB_ICONINFORMATION);
}

void InitListView(HWND hList) {
    ListView_SetExtendedListViewStyle(hList, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);

    LVCOLUMNW lvc = {};
    lvc.mask = LVCF_TEXT | LVCF_WIDTH;

    lvc.pszText = const_cast<LPWSTR>(L"SHA1");
    lvc.cx = 150;
    ListView_InsertColumn(hList, 0, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Chemin");
    lvc.cx = 250;
    ListView_InsertColumn(hList, 1, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Taille");
    lvc.cx = 80;
    ListView_InsertColumn(hList, 2, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Company");
    lvc.cx = 120;
    ListView_InsertColumn(hList, 3, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Product");
    lvc.cx = 120;
    ListView_InsertColumn(hList, 4, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"First Run");
    lvc.cx = 140;
    ListView_InsertColumn(hList, 5, &lvc);

    lvc.pszText = const_cast<LPWSTR>(L"Notes");
    lvc.cx = 150;
    ListView_InsertColumn(hList, 6, &lvc);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_CREATE: {
            // Buttons
            CreateWindowW(L"BUTTON", L"Charger Amcache.hve", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                         10, 10, 150, 25, hwnd, (HMENU)IDC_BTN_LOAD, nullptr, nullptr);

            // Search
            CreateWindowW(L"STATIC", L"Rechercher (SHA1/Chemin) :", WS_CHILD | WS_VISIBLE,
                         170, 15, 150, 20, hwnd, nullptr, nullptr, nullptr);

            g_hEditSearch = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr,
                                            WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
                                            330, 12, 200, 22, hwnd, (HMENU)IDC_EDIT_SEARCH, nullptr, nullptr);

            CreateWindowW(L"BUTTON", L"Chercher", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                         540, 10, 80, 25, hwnd, (HMENU)IDC_BTN_SEARCH, nullptr, nullptr);

            CreateWindowW(L"BUTTON", L"Exporter", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                         630, 10, 80, 25, hwnd, (HMENU)IDC_BTN_EXPORT, nullptr, nullptr);

            // Progress
            g_hProgress = CreateWindowW(PROGRESS_CLASSW, nullptr, WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                                        10, 45, 700, 20, hwnd, (HMENU)IDC_PROGRESS, nullptr, nullptr);
            SendMessageW(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

            // ListView
            g_hListView = CreateWindowExW(0, WC_LISTVIEWW, nullptr,
                                          WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | WS_BORDER,
                                          10, 75, 900, 320, hwnd, (HMENU)IDC_LISTVIEW, nullptr, nullptr);
            InitListView(g_hListView);

            // Status
            g_hStatus = CreateWindowW(L"STATIC", L"Prêt - Cliquez sur Charger Amcache.hve",
                                      WS_CHILD | WS_VISIBLE | SS_LEFT,
                                      10, 405, 900, 20, hwnd, (HMENU)IDC_LABEL_STATUS, nullptr, nullptr);

            // Log
            CreateWindowW(L"STATIC", L"Journal :", WS_CHILD | WS_VISIBLE,
                         10, 430, 100, 20, hwnd, nullptr, nullptr, nullptr);

            g_hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", nullptr,
                                     WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                                     10, 450, 900, 100, hwnd, (HMENU)IDC_EDIT_LOG, nullptr, nullptr);

            Log(L"AmcacheForensics - Analyseur de l'Amcache Windows");
            Log(L"Auteur : Ayi NEDJIMI");
            Log(L"Prêt à charger l'Amcache (exécutez en administrateur).");

            return 0;
        }

        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
                case IDC_BTN_LOAD:
                    OnLoad();
                    break;
                case IDC_BTN_SEARCH:
                    OnSearch();
                    break;
                case IDC_BTN_EXPORT:
                    OnExport();
                    break;
            }
            return 0;
        }

        case WM_DESTROY:
            g_loading = false;
            if (g_hLoadedHive) {
                RegCloseKey(g_hLoadedHive);
                RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"AMCACHE_ANALYSIS");
            }
            PostQuitMessage(0);
            return 0;
    }

    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_LISTVIEW_CLASSES | ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"AmcacheForensicsClass";
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);

    RegisterClassExW(&wc);

    g_hMainWnd = CreateWindowExW(0, wc.lpszClassName,
                                 L"AmcacheForensics - Analyseur Amcache | Ayi NEDJIMI",
                                 WS_OVERLAPPEDWINDOW,
                                 CW_USEDEFAULT, CW_USEDEFAULT, 940, 620,
                                 nullptr, nullptr, hInstance, nullptr);

    ShowWindow(g_hMainWnd, nCmdShow);
    UpdateWindow(g_hMainWnd);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}
