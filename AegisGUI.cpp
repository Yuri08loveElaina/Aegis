// AegisGUI.exe - User Mode Process
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <shlobj.h>
#include <wincrypt.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <map>
#include <thread>
#include <mutex>
#include <condition_variable>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")

// Constants
#define WM_AEGIS_NOTIFY (WM_APP + 1)
#define AEGIS_WINDOW_CLASS L"AegisWindowClass"
#define AEGIS_WINDOW_TITLE L"Project Aegis - Advanced Protection System"

// Threat levels
typedef enum _THREAT_LEVEL {
    THREAT_LEVEL_LOW = 0,
    THREAT_LEVEL_MEDIUM,
    THREAT_LEVEL_HIGH,
    THREAT_LEVEL_CRITICAL
} THREAT_LEVEL;

// Event types
typedef enum _EVENT_TYPE {
    EVENT_TYPE_FILE_CREATE = 1,
    EVENT_TYPE_PROCESS_OPEN,
    EVENT_TYPE_FILE_WRITE,
    EVENT_TYPE_MEMORY_READ,
    EVENT_TYPE_MEMORY_WRITE,
    EVENT_TYPE_FILE_INFO_SET,
    EVENT_TYPE_SECTION_CREATE,
    EVENT_TYPE_ROOTKIT_DETECTED
} EVENT_TYPE;

// Threat structure
typedef struct _THREAT_INFO {
    ULONG ProcessId;
    ULONG ThreadId;
    EVENT_TYPE EventType;
    std::wstring FilePath;
    std::wstring TargetProcess;
    LARGE_INTEGER Timestamp;
    THREAT_LEVEL ThreatLevel;
    std::wstring ThreatName;
    std::wstring Description;
    std::wstring Recommendation;
} THREAT_INFO, *PTHREAT_INFO;

// Global variables
HINSTANCE g_hInstance = NULL;
HWND g_hMainWindow = NULL;
HWND g_hStatusTab = NULL;
HWND g_hHistoryTab = NULL;
HWND g_hManagementTab = NULL;
HWND g_hReportsTab = NULL;
std::vector<THREAT_INFO> g_ThreatHistory;
std::map<std::wstring, bool> g_AllowList;
std::map<std::wstring, bool> g_BlockList;
std::mutex g_ThreatMutex;
std::mutex g_ListMutex;
std::condition_variable g_ThreatCondition;
bool g_Running = true;
HANDLE hDriver = NULL;

// Function prototypes
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
BOOL InitMainWindow(HINSTANCE);
HWND CreateTabControl(HWND);
HWND CreateStatusTab(HWND);
HWND CreateHistoryTab(HWND);
HWND CreateManagementTab(HWND);
HWND CreateReportsTab(HWND);
void ShowThreatNotification(const THREAT_INFO&);
void AnalyzeThreat(THREAT_INFO&);
void HandleThreat(const THREAT_INFO&, DWORD);
void ScanSystem();
void ScanProcesses();
void ScanFiles();
void ScanMemory();
void CheckForRansomware();
bool IsFileBlacklisted(const std::wstring&);
bool IsProcessBlacklisted(const std::wstring&);
bool IsFileAllowed(const std::wstring&);
bool IsProcessAllowed(const std::wstring&);
bool DecryptFile(const std::wstring&, const std::vector<BYTE>&);
std::vector<BYTE> ExtractEncryptionKey(HANDLE);
void UpdateSignatureDatabase();
void LoadConfiguration();
void SaveConfiguration();
void ConnectToDriver();
void DisconnectFromDriver();
DWORD WINAPI ThreatMonitorThread(LPVOID);
DWORD WINAPI SystemScanThread(LPVOID);
INT_PTR CALLBACK ThreatDialogProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK SettingsDialogProc(HWND, UINT, WPARAM, LPARAM);
void AddToHistory(const THREAT_INFO&);
void RefreshHistoryList();
void RefreshManagementList();

// WinMain
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    
    g_hInstance = hInstance;
    
    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icex);
    
    // Load configuration
    LoadConfiguration();
    
    // Connect to kernel driver
    ConnectToDriver();
    
    // Initialize main window
    if (!InitMainWindow(hInstance)) {
        return FALSE;
    }
    
    // Start threat monitor thread
    HANDLE hMonitorThread = CreateThread(NULL, 0, ThreatMonitorThread, NULL, 0, NULL);
    if (hMonitorThread) {
        CloseHandle(hMonitorThread);
    }
    
    // Start system scan thread
    HANDLE hScanThread = CreateThread(NULL, 0, SystemScanThread, NULL, 0, NULL);
    if (hScanThread) {
        CloseHandle(hScanThread);
    }
    
    // Message loop
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    // Disconnect from driver
    DisconnectFromDriver();
    
    // Save configuration
    SaveConfiguration();
    
    return (int)msg.wParam;
}

// Initialize main window
BOOL InitMainWindow(HINSTANCE hInstance) {
    WNDCLASSEX wcex;
    
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_APPLICATION));
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = NULL;
    wcex.lpszClassName = AEGIS_WINDOW_CLASS;
    wcex.hIconSm = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_APPLICATION));
    
    if (!RegisterClassEx(&wcex)) {
        return FALSE;
    }
    
    g_hMainWindow = CreateWindow(
        AEGIS_WINDOW_CLASS,
        AEGIS_WINDOW_TITLE,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        800, 600,
        NULL,
        NULL,
        hInstance,
        NULL
        );
    
    if (!g_hMainWindow) {
        return FALSE;
    }
    
    ShowWindow(g_hMainWindow, SW_SHOW);
    UpdateWindow(g_hMainWindow);
    
    return TRUE;
}

// Window procedure
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_CREATE:
            // Create tab control
            HWND hTab = CreateTabControl(hWnd);
            
            // Create tab pages
            g_hStatusTab = CreateStatusTab(hTab);
            g_hHistoryTab = CreateHistoryTab(hTab);
            g_hManagementTab = CreateManagementTab(hTab);
            g_hReportsTab = CreateReportsTab(hTab);
            
            // Show the first tab
            ShowWindow(g_hStatusTab, SW_SHOW);
            break;
            
        case WM_NOTIFY: {
            NMHDR* pnmh = (NMHDR*)lParam;
            
            // Tab control notifications
            if (pnmh->hwndFrom == GetDlgItem(hWnd, IDC_TAB)) {
                if (pnmh->code == TCN_SELCHANGE) {
                    int iSel = TabCtrl_GetCurSel(pnmh->hwndFrom);
                    
                    // Hide all tabs
                    ShowWindow(g_hStatusTab, SW_HIDE);
                    ShowWindow(g_hHistoryTab, SW_HIDE);
                    ShowWindow(g_hManagementTab, SW_HIDE);
                    ShowWindow(g_hReportsTab, SW_HIDE);
                    
                    // Show selected tab
                    switch (iSel) {
                        case 0:
                            ShowWindow(g_hStatusTab, SW_SHOW);
                            break;
                        case 1:
                            ShowWindow(g_hHistoryTab, SW_SHOW);
                            RefreshHistoryList();
                            break;
                        case 2:
                            ShowWindow(g_hManagementTab, SW_SHOW);
                            RefreshManagementList();
                            break;
                        case 3:
                            ShowWindow(g_hReportsTab, SW_SHOW);
                            break;
                    }
                }
            }
            break;
        }
            
        case WM_AEGIS_NOTIFY: {
            // Threat notification from kernel driver
            PTHREAT_INFO pThreat = (PTHREAT_INFO)lParam;
            if (pThreat) {
                AddToHistory(*pThreat);
                AnalyzeThreat(*pThreat);
                delete pThreat;
            }
            break;
        }
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_FILE_SETTINGS:
                    DialogBox(g_hInstance, MAKEINTRESOURCE(IDD_SETTINGS), hWnd, SettingsDialogProc);
                    break;
                    
                case ID_FILE_EXIT:
                    DestroyWindow(hWnd);
                    break;
                    
                case ID_SCAN_QUICK:
                    std::thread(ScanSystem).detach();
                    break;
                    
                case ID_SCAN_FULL:
                    std::thread([]() {
                        ScanProcesses();
                        ScanFiles();
                        ScanMemory();
                    }).detach();
                    break;
                    
                case ID_HELP_ABOUT:
                    MessageBox(hWnd, L"Project Aegis - Advanced Protection System\nVersion 1.0", L"About", MB_OK | MB_ICONINFORMATION);
                    break;
            }
            break;
            
        case WM_DESTROY:
            g_Running = false;
            g_ThreatCondition.notify_all();
            PostQuitMessage(0);
            break;
            
        default:
            return DefWindowProc(hWnd, message, wParam, lParam);
    }
    
    return 0;
}

// Create tab control
HWND CreateTabControl(HWND hWndParent) {
    HWND hTab = CreateWindow(
        WC_TABCONTROL,
        NULL,
        WS_CHILD | WS_CLIPSIBLINGS | WS_VISIBLE,
        0, 0, 0, 0,
        hWndParent,
        (HMENU)IDC_TAB,
        g_hInstance,
        NULL
        );
    
    // Add tabs
    TCITEM tie;
    tie.mask = TCIF_TEXT;
    
    tie.pszText = L"Dashboard";
    TabCtrl_InsertItem(hTab, 0, &tie);
    
    tie.pszText = L"History";
    TabCtrl_InsertItem(hTab, 1, &tie);
    
    tie.pszText = L"Management";
    TabCtrl_InsertItem(hTab, 2, &tie);
    
    tie.pszText = L"Reports";
    TabCtrl_InsertItem(hTab, 3, &tie);
    
    // Position the tab control
    RECT rcClient;
    GetClientRect(hWndParent, &rcClient);
    SetWindowPos(hTab, NULL, 0, 0, rcClient.right, rcClient.bottom, SWP_NOZORDER);
    
    return hTab;
}

// Create status tab
HWND CreateStatusTab(HWND hWndParent) {
    HWND hTab = CreateWindow(
        WC_DIALOG,
        NULL,
        WS_CHILD | DS_CONTROL,
        10, 40, 760, 510,
        hWndParent,
        NULL,
        g_hInstance,
        NULL
        );
    
    // Status display
    CreateWindow(
        WC_STATIC,
        L"Protection Status:",
        WS_CHILD | WS_VISIBLE,
        20, 20, 150, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_STATIC,
        L"ACTIVE",
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        180, 20, 100, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    // Threats blocked
    CreateWindow(
        WC_STATIC,
        L"Threats Blocked:",
        WS_CHILD | WS_VISIBLE,
        20, 60, 150, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    HWND hThreatsBlocked = CreateWindow(
        WC_STATIC,
        L"0",
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        180, 60, 100, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    // Last scan
    CreateWindow(
        WC_STATIC,
        L"Last Scan:",
        WS_CHILD | WS_VISIBLE,
        20, 100, 150, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_STATIC,
        L"Never",
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        180, 100, 200, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    // Scan buttons
    CreateWindow(
        WC_BUTTON,
        L"Quick Scan",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, 150, 120, 30,
        hTab,
        (HMENU)ID_SCAN_QUICK,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_BUTTON,
        L"Full Scan",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        160, 150, 120, 30,
        hTab,
        (HMENU)ID_SCAN_FULL,
        g_hInstance,
        NULL
        );
    
    // Real-time protection status
    CreateWindow(
        WC_STATIC,
        L"Real-time Protection:",
        WS_CHILD | WS_VISIBLE,
        20, 200, 150, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_BUTTON,
        L"Enabled",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | BS_CHECKED,
        180, 200, 100, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    // Firewall status
    CreateWindow(
        WC_STATIC,
        L"Firewall:",
        WS_CHILD | WS_VISIBLE,
        20, 240, 150, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_BUTTON,
        L"Enabled",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX | BS_CHECKED,
        180, 240, 100, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    // Update status
    CreateWindow(
        WC_STATIC,
        L"Last Update:",
        WS_CHILD | WS_VISIBLE,
        20, 280, 150, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_STATIC,
        L"Today",
        WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE,
        180, 280, 200, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    // Update button
    CreateWindow(
        WC_BUTTON,
        L"Update Now",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, 320, 120, 30,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    return hTab;
}

// Create history tab
HWND CreateHistoryTab(HWND hWndParent) {
    HWND hTab = CreateWindow(
        WC_DIALOG,
        NULL,
        WS_CHILD | DS_CONTROL,
        10, 40, 760, 510,
        hWndParent,
        NULL,
        g_hInstance,
        NULL
        );
    
    // History list
    HWND hList = CreateWindow(
        WC_LISTVIEW,
        NULL,
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        20, 20, 720, 400,
        hTab,
        (HMENU)IDC_HISTORY_LIST,
        g_hInstance,
        NULL
        );
    
    // Add columns
    LVCOLUMN lvc;
    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    
    lvc.iSubItem = 0;
    lvc.pszText = const_cast<LPWSTR>(L"Time");
    lvc.cx = 120;
    lvc.fmt = LVCFMT_LEFT;
    ListView_InsertColumn(hList, 0, &lvc);
    
    lvc.iSubItem = 1;
    lvc.pszText = const_cast<LPWSTR>(L"Threat");
    lvc.cx = 150;
    ListView_InsertColumn(hList, 1, &lvc);
    
    lvc.iSubItem = 2;
    lvc.pszText = const_cast<LPWSTR>(L"Level");
    lvc.cx = 80;
    ListView_InsertColumn(hList, 2, &lvc);
    
    lvc.iSubItem = 3;
    lvc.pszText = const_cast<LPWSTR>(L"File/Process");
    lvc.cx = 200;
    ListView_InsertColumn(hList, 3, &lvc);
    
    lvc.iSubItem = 4;
    lvc.pszText = const_cast<LPWSTR>(L"Action");
    lvc.cx = 100;
    ListView_InsertColumn(hList, 4, &lvc);
    
    // Buttons
    CreateWindow(
        WC_BUTTON,
        L"Clear History",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, 440, 120, 30,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_BUTTON,
        L"Export",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        160, 440, 120, 30,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    return hTab;
}

// Create management tab
HWND CreateManagementTab(HWND hWndParent) {
    HWND hTab = CreateWindow(
        WC_DIALOG,
        NULL,
        WS_CHILD | DS_CONTROL,
        10, 40, 760, 510,
        hWndParent,
        NULL,
        g_hInstance,
        NULL
        );
    
    // Allow list
    CreateWindow(
        WC_STATIC,
        L"Allowed Items:",
        WS_CHILD | WS_VISIBLE,
        20, 20, 150, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    HWND hAllowList = CreateWindow(
        WC_LISTBOX,
        NULL,
        WS_CHILD | WS_VISIBLE | LBS_STANDARD | LBS_NOINTEGRALHEIGHT,
        20, 50, 350, 200,
        hTab,
        (HMENU)IDC_ALLOW_LIST,
        g_hInstance,
        NULL
        );
    
    // Block list
    CreateWindow(
        WC_STATIC,
        L"Blocked Items:",
        WS_CHILD | WS_VISIBLE,
        390, 20, 150, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    HWND hBlockList = CreateWindow(
        WC_LISTBOX,
        NULL,
        WS_CHILD | WS_VISIBLE | LBS_STANDARD | LBS_NOINTEGRALHEIGHT,
        390, 50, 350, 200,
        hTab,
        (HMENU)IDC_BLOCK_LIST,
        g_hInstance,
        NULL
        );
    
    // Buttons
    CreateWindow(
        WC_BUTTON,
        L"Add Item",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, 270, 120, 30,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_BUTTON,
        L"Remove Item",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        160, 270, 120, 30,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_BUTTON,
        L"Import List",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, 320, 120, 30,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_BUTTON,
        L"Export List",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        160, 320, 120, 30,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    // Quarantine section
    CreateWindow(
        WC_STATIC,
        L"Quarantine:",
        WS_CHILD | WS_VISIBLE,
        20, 380, 150, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_BUTTON,
        L"View Quarantine",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, 410, 120, 30,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_BUTTON,
        L"Restore Item",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        160, 410, 120, 30,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    return hTab;
}

// Create reports tab
HWND CreateReportsTab(HWND hWndParent) {
    HWND hTab = CreateWindow(
        WC_DIALOG,
        NULL,
        WS_CHILD | DS_CONTROL,
        10, 40, 760, 510,
        hWndParent,
        NULL,
        g_hInstance,
        NULL
        );
    
    // Report selection
    CreateWindow(
        WC_STATIC,
        L"Select Report:",
        WS_CHILD | WS_VISIBLE,
        20, 20, 150, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    HWND hReportCombo = CreateWindow(
        WC_COMBOBOX,
        NULL,
        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
        20, 50, 300, 200,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    // Add report types
    SendMessage(hReportCombo, CB_ADDSTRING, 0, (LPARAM)L"Threat Detection Report");
    SendMessage(hReportCombo, CB_ADDSTRING, 0, (LPARAM)L"System Scan Report");
    SendMessage(hReportCombo, CB_ADDSTRING, 0, (LPARAM)L"Network Activity Report");
    SendMessage(hReportCombo, CB_ADDSTRING, 0, (LPARAM)L"File Access Report");
    SendMessage(hReportCombo, CB_SETCURSEL, 0, 0);
    
    // Date range
    CreateWindow(
        WC_STATIC,
        L"Date Range:",
        WS_CHILD | WS_VISIBLE,
        20, 90, 150, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_STATIC,
        L"From:",
        WS_CHILD | WS_VISIBLE,
        20, 120, 50, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_DATETIMEPICK,
        NULL,
        WS_CHILD | WS_VISIBLE | DTS_SHORTDATEFORMAT,
        80, 120, 120, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_STATIC,
        L"To:",
        WS_CHILD | WS_VISIBLE,
        220, 120, 50, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    CreateWindow(
        WC_DATETIMEPICK,
        NULL,
        WS_CHILD | WS_VISIBLE | DTS_SHORTDATEFORMAT,
        280, 120, 120, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    // Generate button
    CreateWindow(
        WC_BUTTON,
        L"Generate Report",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, 160, 120, 30,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    // Report view
    CreateWindow(
        WC_STATIC,
        L"Report Preview:",
        WS_CHILD | WS_VISIBLE,
        20, 210, 150, 20,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    HWND hReportView = CreateWindow(
        WC_EDIT,
        L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY | WS_VSCROLL,
        20, 240, 720, 230,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    // Export button
    CreateWindow(
        WC_BUTTON,
        L"Export Report",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, 480, 120, 30,
        hTab,
        NULL,
        g_hInstance,
        NULL
        );
    
    return hTab;
}

// Show threat notification
void ShowThreatNotification(const THREAT_INFO& threat) {
    // Create dialog with threat information
    DialogBoxParam(
        g_hInstance,
        MAKEINTRESOURCE(IDD_THREAT_DIALOG),
        g_hMainWindow,
        ThreatDialogProc,
        (LPARAM)&threat
        );
}

// Analyze threat
void AnalyzeThreat(THREAT_INFO& threat) {
    // Default threat level
    threat.ThreatLevel = THREAT_LEVEL_LOW;
    
    // Check against allow/block lists
    if (!threat.FilePath.empty()) {
        if (IsFileAllowed(threat.FilePath)) {
            threat.ThreatLevel = THREAT_LEVEL_LOW;
            threat.ThreatName = L"Allowed File";
            threat.Description = L"This file is in the allow list.";
            threat.Recommendation = L"Allow";
            return;
        }
        
        if (IsFileBlacklisted(threat.FilePath)) {
            threat.ThreatLevel = THREAT_LEVEL_CRITICAL;
            threat.ThreatName = L"Blacklisted File";
            threat.Description = L"This file is known to be malicious.";
            threat.Recommendation = L"Remove";
            HandleThreat(threat, 0); // Auto-remove blacklisted items
            return;
        }
    }
    
    if (!threat.TargetProcess.empty()) {
        if (IsProcessAllowed(threat.TargetProcess)) {
            threat.ThreatLevel = THREAT_LEVEL_LOW;
            threat.ThreatName = L"Allowed Process";
            threat.Description = L"This process is in the allow list.";
            threat.Recommendation = L"Allow";
            return;
        }
        
        if (IsProcessBlacklisted(threat.TargetProcess)) {
            threat.ThreatLevel = THREAT_LEVEL_CRITICAL;
            threat.ThreatName = L"Blacklisted Process";
            threat.Description = L"This process is known to be malicious.";
            threat.Recommendation = L"Remove";
            HandleThreat(threat, 0); // Auto-remove blacklisted items
            return;
        }
    }
    
    // Analyze based on event type
    switch (threat.EventType) {
        case EVENT_TYPE_FILE_CREATE:
            // Check file extension and location
            if (threat.FilePath.find(L".exe") != std::wstring::npos ||
                threat.FilePath.find(L".dll") != std::wstring::npos ||
                threat.FilePath.find(L".sys") != std::wstring::npos) {
                
                // Check if it's in a suspicious location
                if (threat.FilePath.find(L"\\Temp\\") != std::wstring::npos ||
                    threat.FilePath.find(L"\\AppData\\Local\\Temp\\") != std::wstring::npos) {
                    
                    threat.ThreatLevel = THREAT_LEVEL_MEDIUM;
                    threat.ThreatName = L"Suspicious Executable";
                    threat.Description = L"An executable file was created in a temporary directory.";
                    threat.Recommendation = L"Quarantine";
                }
            }
            break;
            
        case EVENT_TYPE_PROCESS_OPEN:
            // Check if target is a sensitive process
            if (threat.TargetProcess.find(L"explorer.exe") != std::wstring::npos ||
                threat.TargetProcess.find(L"lsass.exe") != std::wstring::npos ||
                threat.TargetProcess.find(L"csrss.exe") != std::wstring::npos) {
                
                threat.ThreatLevel = THREAT_LEVEL_HIGH;
                threat.ThreatName = L"Sensitive Process Access";
                threat.Description = L"A process attempted to access a sensitive system process.";
                threat.Recommendation = L"Block";
            }
            break;
            
        case EVENT_TYPE_FILE_WRITE:
            // Check for ransomware-like behavior
            if (threat.FilePath.find(L".encrypted") != std::wstring::npos ||
                threat.FilePath.find(L".locked") != std::wstring::npos ||
                threat.FilePath.find(L".crypted") != std::wstring::npos) {
                
                threat.ThreatLevel = THREAT_LEVEL_CRITICAL;
                threat.ThreatName = L"Ransomware Activity";
                threat.Description = L"Files with ransomware extensions are being created.";
                threat.Recommendation = L"Remove";
                HandleThreat(threat, 0); // Auto-remove ransomware
            }
            break;
            
        case EVENT_TYPE_MEMORY_WRITE:
            // Check for code injection
            threat.ThreatLevel = THREAT_LEVEL_HIGH;
            threat.ThreatName = L"Memory Write";
            threat.Description = L"A process is writing to another process's memory.";
            threat.Recommendation = L"Block";
            break;
            
        case EVENT_TYPE_ROOTKIT_DETECTED:
            threat.ThreatLevel = THREAT_LEVEL_CRITICAL;
            threat.ThreatName = L"Rootkit Detected";
            threat.Description = L"A rootkit was detected in the system.";
            threat.Recommendation = L"Remove";
            HandleThreat(threat, 0); // Auto-remove rootkits
            break;
    }
    
    // If threat level is high or critical, show notification
    if (threat.ThreatLevel >= THREAT_LEVEL_HIGH) {
        PostMessage(g_hMainWindow, WM_AEGIS_NOTIFY, 0, (LPARAM)new THREAT_INFO(threat));
    }
}

// Handle threat
void HandleThreat(const THREAT_INFO& threat, DWORD action) {
    switch (action) {
        case 0: // Remove
            // Terminate process if applicable
            if (threat.ProcessId != (ULONG)-1 && threat.ProcessId != 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, threat.ProcessId);
                if (hProcess) {
                    TerminateProcess(hProcess, 1);
                    CloseHandle(hProcess);
                }
            }
            
            // Delete file if applicable
            if (!threat.FilePath.empty()) {
                DeleteFile(threat.FilePath.c_str());
            }
            break;
            
        case 1: // Quarantine
            // Move file to quarantine
            if (!threat.FilePath.empty()) {
                WCHAR quarantinePath[MAX_PATH];
                ExpandEnvironmentStrings(L"%APPDATA%\\Aegis\\Quarantine", quarantinePath, MAX_PATH);
                CreateDirectory(quarantinePath, NULL);
                
                WCHAR fileName[MAX_PATH];
                WCHAR fileExt[MAX_PATH];
                _wsplitpath_s(threat.FilePath.c_str(), NULL, 0, NULL, 0, fileName, MAX_PATH, fileExt, MAX_PATH);
                
                WCHAR quarantineFile[MAX_PATH];
                swprintf_s(quarantineFile, L"%s\\%s_%llu%s", quarantinePath, fileName, threat.Timestamp.QuadPart, fileExt);
                
                MoveFile(threat.FilePath.c_str(), quarantineFile);
            }
            break;
            
        case 2: // Allow
            // Add to allow list
            if (!threat.FilePath.empty()) {
                std::lock_guard<std::mutex> lock(g_ListMutex);
                g_AllowList[threat.FilePath] = true;
            }
            if (!threat.TargetProcess.empty()) {
                std::lock_guard<std::mutex> lock(g_ListMutex);
                g_AllowList[threat.TargetProcess] = true;
            }
            break;
    }
}

// Scan system
void ScanSystem() {
    ScanProcesses();
    ScanFiles();
    ScanMemory();
    CheckForRansomware();
}

// Scan processes
void ScanProcesses() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Check if process is blacklisted
            if (IsProcessBlacklisted(pe32.szExeFile)) {
                THREAT_INFO threat;
                threat.ProcessId = pe32.th32ProcessID;
                threat.ThreadId = 0;
                threat.EventType = EVENT_TYPE_PROCESS_OPEN;
                threat.TargetProcess = pe32.szExeFile;
                threat.ThreatLevel = THREAT_LEVEL_CRITICAL;
                threat.ThreatName = L"Blacklisted Process";
                threat.Description = L"A known malicious process is running.";
                threat.Recommendation = L"Remove";
                KeQuerySystemTime(&threat.Timestamp);
                
                AddToHistory(threat);
                HandleThreat(threat, 0); // Auto-remove
            }
            
            // Check for suspicious process names
            if (wcsstr(pe32.szExeFile, L"crypt") != NULL ||
                wcsstr(pe32.szExeFile, L"lock") != NULL ||
                wcsstr(pe32.szExeFile, L"decrypt") != NULL) {
                
                THREAT_INFO threat;
                threat.ProcessId = pe32.th32ProcessID;
                threat.ThreadId = 0;
                threat.EventType = EVENT_TYPE_PROCESS_OPEN;
                threat.TargetProcess = pe32.szExeFile;
                threat.ThreatLevel = THREAT_LEVEL_MEDIUM;
                threat.ThreatName = L"Suspicious Process";
                threat.Description = L"A process with a suspicious name is running.";
                threat.Recommendation = L"Quarantine";
                KeQuerySystemTime(&threat.Timestamp);
                
                AddToHistory(threat);
            }
            
            // Check for processes without visible windows
            HWND hWnd = NULL;
            DWORD dwProcessId;
            do {
                hWnd = FindWindowEx(NULL, hWnd, NULL, NULL);
                if (hWnd) {
                    GetWindowThreadProcessId(hWnd, &dwProcessId);
                    if (dwProcessId == pe32.th32ProcessID) {
                        break;
                    }
                }
            } while (hWnd != NULL);
            
            if (hWnd == NULL && pe32.th32ProcessID > 0 && pe32.th32ProcessID < 10000) {
                // Check if it's a known system process
                bool isSystemProcess = false;
                const WCHAR* systemProcesses[] = {
                    L"svchost.exe", L"csrss.exe", L"wininit.exe", L"services.exe",
                    L"lsass.exe", L"winlogon.exe", L"explorer.exe", L"System"
                };
                
                for (const WCHAR* proc : systemProcesses) {
                    if (_wcsicmp(pe32.szExeFile, proc) == 0) {
                        isSystemProcess = true;
                        break;
                    }
                }
                
                if (!isSystemProcess) {
                    THREAT_INFO threat;
                    threat.ProcessId = pe32.th32ProcessID;
                    threat.ThreadId = 0;
                    threat.EventType = EVENT_TYPE_PROCESS_OPEN;
                    threat.TargetProcess = pe32.szExeFile;
                    threat.ThreatLevel = THREAT_LEVEL_MEDIUM;
                    threat.ThreatName = L"Hidden Process";
                    threat.Description = L"A process without visible windows is running.";
                    threat.Recommendation = L"Quarantine";
                    KeQuerySystemTime(&threat.Timestamp);
                    
                    AddToHistory(threat);
                }
            }
            
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
}

// Scan files
void ScanFiles() {
    // Scan common directories for malware
    WCHAR tempPath[MAX_PATH];
    GetTempPath(MAX_PATH, tempPath);
    
    WCHAR appDataPath[MAX_PATH];
    ExpandEnvironmentStrings(L"%APPDATA%", appDataPath, MAX_PATH);
    
    // Scan temp directory
    WIN32_FIND_DATA findData;
    HANDLE hFind = FindFirstFile(std::wstring(tempPath) + L"\\*.exe", &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring filePath = std::wstring(tempPath) + L"\\" + findData.cFileName;
            
            // Check file signature
            if (IsFileBlacklisted(filePath)) {
                THREAT_INFO threat;
                threat.ProcessId = 0;
                threat.ThreadId = 0;
                threat.EventType = EVENT_TYPE_FILE_CREATE;
                threat.FilePath = filePath;
                threat.ThreatLevel = THREAT_LEVEL_CRITICAL;
                threat.ThreatName = L"Blacklisted File";
                threat.Description = L"A known malicious file was found.";
                threat.Recommendation = L"Remove";
                KeQuerySystemTime(&threat.Timestamp);
                
                AddToHistory(threat);
                HandleThreat(threat, 0); // Auto-remove
            }
            
        } while (FindNextFile(hFind, &findData));
        
        FindClose(hFind);
    }
    
    // Scan AppData directory
    hFind = FindFirstFile(std::wstring(appDataPath) + L"\\*.exe", &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring filePath = std::wstring(appDataPath) + L"\\" + findData.cFileName;
            
            // Check file signature
            if (IsFileBlacklisted(filePath)) {
                THREAT_INFO threat;
                threat.ProcessId = 0;
                threat.ThreadId = 0;
                threat.EventType = EVENT_TYPE_FILE_CREATE;
                threat.FilePath = filePath;
                threat.ThreatLevel = THREAT_LEVEL_CRITICAL;
                threat.ThreatName = L"Blacklisted File";
                threat.Description = L"A known malicious file was found.";
                threat.Recommendation = L"Remove";
                KeQuerySystemTime(&threat.Timestamp);
                
                AddToHistory(threat);
                HandleThreat(threat, 0); // Auto-remove
            }
            
        } while (FindNextFile(hFind, &findData));
        
        FindClose(hFind);
    }
}

// Scan memory
void ScanMemory() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPMODULE, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                // Enumerate modules
                MODULEENTRY32 me32;
                me32.dwSize = sizeof(MODULEENTRY32);
                
                HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pe32.th32ProcessID);
                if (hModuleSnapshot != INVALID_HANDLE_VALUE) {
                    if (Module32First(hModuleSnapshot, &me32)) {
                        do {
                            // Check if module is blacklisted
                            if (IsFileBlacklisted(me32.szExePath)) {
                                THREAT_INFO threat;
                                threat.ProcessId = pe32.th32ProcessID;
                                threat.ThreadId = 0;
                                threat.EventType = EVENT_TYPE_MEMORY_WRITE;
                                threat.FilePath = me32.szExePath;
                                threat.TargetProcess = pe32.szExeFile;
                                threat.ThreatLevel = THREAT_LEVEL_CRITICAL;
                                threat.ThreatName = L"Blacklisted Module";
                                threat.Description = L"A known malicious module is loaded in a process.";
                                threat.Recommendation = L"Remove";
                                KeQuerySystemTime(&threat.Timestamp);
                                
                                AddToHistory(threat);
                                HandleThreat(threat, 0); // Auto-remove
                            }
                            
                        } while (Module32Next(hModuleSnapshot, &me32));
                    }
                    
                    CloseHandle(hModuleSnapshot);
                }
                
                CloseHandle(hProcess);
            }
            
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
}

// Check for ransomware
void CheckForRansomware() {
    // Look for files with ransomware extensions
    WCHAR userProfile[MAX_PATH];
    ExpandEnvironmentStrings(L"%USERPROFILE%", userProfile, MAX_PATH);
    
    // Scan Documents folder
    WIN32_FIND_DATA findData;
    HANDLE hFind = FindFirstFile(std::wstring(userProfile) + L"\\Documents\\*.encrypted", &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring filePath = std::wstring(userProfile) + L"\\Documents\\" + findData.cFileName;
            
            THREAT_INFO threat;
            threat.ProcessId = 0;
            threat.ThreadId = 0;
            threat.EventType = EVENT_TYPE_FILE_WRITE;
            threat.FilePath = filePath;
            threat.ThreatLevel = THREAT_LEVEL_CRITICAL;
            threat.ThreatName = L"Encrypted File Detected";
            threat.Description = L"A file with a ransomware extension was found.";
            threat.Recommendation = L"Decrypt";
            KeQuerySystemTime(&threat.Timestamp);
            
            AddToHistory(threat);
            
        } while (FindNextFile(hFind, &findData));
        
        FindClose(hFind);
    }
    
    // Look for ransomware processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (Process32First(hSnapshot, &pe32)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                // Check for encryption keys in memory
                std::vector<BYTE> encryptionKey = ExtractEncryptionKey(hProcess);
                if (!encryptionKey.empty()) {
                    THREAT_INFO threat;
                    threat.ProcessId = pe32.th32ProcessID;
                    threat.ThreadId = 0;
                    threat.EventType = EVENT_TYPE_MEMORY_WRITE;
                    threat.TargetProcess = pe32.szExeFile;
                    threat.ThreatLevel = THREAT_LEVEL_CRITICAL;
                    threat.ThreatName = L"Ransomware Process";
                    threat.Description = L"A process containing encryption keys was found.";
                    threat.Recommendation = L"Remove";
                    KeQuerySystemTime(&threat.Timestamp);
                    
                    AddToHistory(threat);
                    HandleThreat(threat, 0); // Auto-remove
                    
                    // Attempt to decrypt files
                    hFind = FindFirstFile(std::wstring(userProfile) + L"\\Documents\\*.encrypted", &findData);
                    if (hFind != INVALID_HANDLE_VALUE) {
                        do {
                            std::wstring filePath = std::wstring(userProfile) + L"\\Documents\\" + findData.cFileName;
                            DecryptFile(filePath, encryptionKey);
                        } while (FindNextFile(hFind, &findData));
                        
                        FindClose(hFind);
                    }
                }
                
                CloseHandle(hProcess);
            }
            
        } while (Process32Next(hSnapshot, &pe32));
    }
    
    CloseHandle(hSnapshot);
}

// Check if file is blacklisted
bool IsFileBlacklisted(const std::wstring& filePath) {
    std::lock_guard<std::mutex> lock(g_ListMutex);
    
    // Check file name
    std::wstring fileName = filePath;
    size_t pos = fileName.find_last_of(L"\\");
    if (pos != std::wstring::npos) {
        fileName = fileName.substr(pos + 1);
    }
    
    // Check against block list
    for (const auto& item : g_BlockList) {
        if (filePath.find(item.first) != std::wstring::npos ||
            fileName.find(item.first) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

// Check if process is blacklisted
bool IsProcessBlacklisted(const std::wstring& processName) {
    std::lock_guard<std::mutex> lock(g_ListMutex);
    
    // Check against block list
    for (const auto& item : g_BlockList) {
        if (processName.find(item.first) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

// Check if file is allowed
bool IsFileAllowed(const std::wstring& filePath) {
    std::lock_guard<std::mutex> lock(g_ListMutex);
    
    // Check file name
    std::wstring fileName = filePath;
    size_t pos = fileName.find_last_of(L"\\");
    if (pos != std::wstring::npos) {
        fileName = fileName.substr(pos + 1);
    }
    
    // Check against allow list
    for (const auto& item : g_AllowList) {
        if (filePath.find(item.first) != std::wstring::npos ||
            fileName.find(item.first) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

// Check if process is allowed
bool IsProcessAllowed(const std::wstring& processName) {
    std::lock_guard<std::mutex> lock(g_ListMutex);
    
    // Check against allow list
    for (const auto& item : g_AllowList) {
        if (processName.find(item.first) != std::wstring::npos) {
            return true;
        }
    }
    
    return false;
}

// Decrypt file
bool DecryptFile(const std::wstring& filePath, const std::vector<BYTE>& key) {
    if (key.empty()) {
        return false;
    }
    
    // Open encrypted file
    HANDLE hFile = CreateFile(
        filePath.c_str(),
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
        );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }
    
    // Get file size
    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }
    
    // Allocate buffer for file content
    std::vector<BYTE> fileContent(fileSize);
    DWORD bytesRead;
    
    // Read file content
    if (!ReadFile(hFile, fileContent.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        CloseHandle(hFile);
        return false;
    }
    
    // Simple XOR decryption (in a real implementation, use proper crypto)
    for (size_t i = 0; i < fileContent.size(); i++) {
        fileContent[i] ^= key[i % key.size()];
    }
    
    // Move file pointer to beginning
    SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
    
    // Write decrypted content
    DWORD bytesWritten;
    if (!WriteFile(hFile, fileContent.data(), fileSize, &bytesWritten, NULL) || bytesWritten != fileSize) {
        CloseHandle(hFile);
        return false;
    }
    
    // Close file
    CloseHandle(hFile);
    
    // Remove .encrypted extension
    std::wstring newFilePath = filePath;
    size_t extPos = newFilePath.find(L".encrypted");
    if (extPos != std::wstring::npos) {
        newFilePath = newFilePath.substr(0, extPos);
        MoveFile(filePath.c_str(), newFilePath.c_str());
    }
    
    return true;
}

// Extract encryption key from process memory
std::vector<BYTE> ExtractEncryptionKey(HANDLE hProcess) {
    std::vector<BYTE> key;
    
    // Get process memory information
    MEMORY_BASIC_INFORMATION mbi;
    for (LPVOID addr = 0; 
         VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi); 
         addr = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize)) {
        
        // Skip non-committed pages
        if (!(mbi.State & MEM_COMMIT)) {
            continue;
        }
        
        // Skip pages we can't read
        if (!(mbi.Protect & PAGE_READWRITE)) {
            continue;
        }
        
        // Read memory region
        std::vector<BYTE> buffer(mbi.RegionSize);
        SIZE_T bytesRead;
        if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer.data(), mbi.RegionSize, &bytesRead)) {
            // Look for encryption key patterns
            
            // Look for AES key length (16, 24, or 32 bytes)
            const size_t keySizes[] = { 16, 24, 32 };
            
            for (size_t keySize : keySizes) {
                for (size_t i = 0; i <= bytesRead - keySize; i++) {
                    // Check if this could be a key
                    bool couldBeKey = true;
                    
                    // Check for entropy (simplified)
                    BYTE entropy = 0;
                    for (size_t j = 0; j < keySize; j++) {
                        entropy |= buffer[i + j];
                    }
                    
                    // If all zeros, probably not a key
                    if (entropy == 0) {
                        couldBeKey = false;
                    }
                    
                    // If all the same byte, probably not a key
                    if (couldBeKey) {
                        bool allSame = true;
                        for (size_t j = 1; j < keySize; j++) {
                            if (buffer[i + j] != buffer[i]) {
                                allSame = false;
                                break;
                            }
                        }
                        
                        if (allSame) {
                            couldBeKey = false;
                        }
                    }
                    
                    // If it passes our checks, consider it a potential key
                    if (couldBeKey) {
                        key.assign(buffer.begin() + i, buffer.begin() + i + keySize);
                        return key;
                    }
                }
            }
        }
    }
    
    return key;
}

// Update signature database
void UpdateSignatureDatabase() {
    
    std::lock_guard<std::mutex> lock(g_ListMutex);
    
    // Add common ransomware names
    g_BlockList[L"wannacry"] = true;
    g_BlockList[L"petya"] = true;
    g_BlockList[L"notpetya"] = true;
    g_BlockList[L"badrabbit"] = true;
    g_BlockList[L"ryuk"] = true;
    g_BlockList[L"sodinokibi"] = true;
    g_BlockList[L"locky"] = true;
    g_BlockList[L"cryptolocker"] = true;
    g_BlockList[L"cerber"] = true;
    g_BlockList[L"zeus"] = true;
    g_BlockList[L"conficker"] = true;
    
    // Add common trojan names
    g_BlockList[L"backdoor"] = true;
    g_BlockList[L"keylogger"] = true;
    g_BlockList[L"stealer"] = true;
    g_BlockList[L"spyware"] = true;
    g_BlockList[L"rootkit"] = true;
    
    // Add common suspicious file extensions
    g_BlockList[L".scr"] = true;
    g_BlockList[L".pif"] = true;
    g_BlockList[L".com"] = true;
    g_BlockList[L".bat"] = true;
    g_BlockList[L".cmd"] = true;
    g_BlockList[L".vbs"] = true;
    g_BlockList[L".js"] = true;
    g_BlockList[L".jar"] = true;
}

// Load configuration
void LoadConfiguration() {
    
    // Add some common system processes to the allow list
    g_AllowList[L"explorer.exe"] = true;
    g_AllowList[L"svchost.exe"] = true;
    g_AllowList[L"lsass.exe"] = true;
    g_AllowList[L"csrss.exe"] = true;
    g_AllowList[L"wininit.exe"] = true;
    g_AllowList[L"services.exe"] = true;
    g_AllowList[L"winlogon.exe"] = true;
    g_AllowList[L"System"] = true;
    
    // Add some common system directories to the allow list
    g_AllowList[L"C:\\Windows\\System32\\"] = true;
    g_AllowList[L"C:\\Windows\\SysWOW64\\"] = true;
    g_AllowList[L"C:\\Program Files\\"] = true;
    g_AllowList[L"C:\\Program Files (x86)\\"] = true;
    
    // Load signature database
    UpdateSignatureDatabase();
}

// Save configuration
void SaveConfiguration() {
    // In a real implementation, this would save configuration to the registry or a file
    // For this example, we'll do nothing
}

// Connect to kernel driver
void ConnectToDriver() {
    // In a real implementation, this would open a handle to the kernel driver
    // For this example, we'll just create a dummy handle
    
    hDriver = CreateFile(
        L"\\\\.\\AegisKernel",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
        );
    
    if (hDriver == INVALID_HANDLE_VALUE) {
        // Driver not loaded, try to load it
        SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (hSCManager) {
            SC_HANDLE hService = OpenService(hSCManager, L"AegisKernel", SERVICE_ALL_ACCESS);
            if (!hService) {
                // Service doesn't exist, create it
                WCHAR driverPath[MAX_PATH];
                GetModuleFileName(NULL, driverPath, MAX_PATH);
                
                WCHAR* lastSlash = wcsrchr(driverPath, L'\\');
                if (lastSlash) {
                    *lastSlash = L'\0';
                    wcscat_s(driverPath, L"\\AegisKernel.sys");
                }
                
                hService = CreateService(
                    hSCManager,
                    L"AegisKernel",
                    L"Aegis Kernel Driver",
                    SERVICE_ALL_ACCESS,
                    SERVICE_KERNEL_DRIVER,
                    SERVICE_DEMAND_START,
                    SERVICE_ERROR_NORMAL,
                    driverPath,
                    NULL, NULL, NULL, NULL, NULL
                    );
            }
            
            if (hService) {
                // Start the service
                StartService(hService, 0, NULL);
                CloseServiceHandle(hService);
                
                // Try to connect again
                hDriver = CreateFile(
                    L"\\\\.\\AegisKernel",
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    NULL,
                    OPEN_EXISTING,
                    0,
                    NULL
                    );
            }
            
            CloseServiceHandle(hSCManager);
        }
    }
}

// Disconnect from kernel driver
void DisconnectFromDriver() {
    if (hDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(hDriver);
        hDriver = INVALID_HANDLE_VALUE;
    }
}

// Threat monitor thread
DWORD WINAPI ThreatMonitorThread(LPVOID lpParam) {
    UNREFERENCED_PARAMETER(lpParam);
    
    while (g_Running) {
        // In a real implementation, this would receive events from the kernel driver
        // For this example, we'll just simulate some events
        
        std::unique_lock<std::mutex> lock(g_ThreatMutex);
        g_ThreatCondition.wait_for(lock, std::chrono::seconds(5), [] { return !g_Running; });
        
        if (!g_Running) {
            break;
        }
        
        // Simulate a threat event
        static int counter = 0;
        counter++;
        
        if (counter % 10 == 0) {
            // Every 50 seconds, simulate a threat
            THREAT_INFO threat;
            threat.ProcessId = 1234 + counter;
            threat.ThreadId = 5678 + counter;
            threat.EventType = (EVENT_TYPE)(counter % 8);
            threat.FilePath = L"C:\\Temp\\suspicious_file.exe";
            threat.TargetProcess = L"suspicious_process.exe";
            threat.ThreatLevel = (THREAT_LEVEL)(counter % 4);
            threat.ThreatName = L"Suspicious Activity";
            threat.Description = L"A suspicious activity was detected.";
            threat.Recommendation = L"Quarantine";
            KeQuerySystemTime(&threat.Timestamp);
            
            AddToHistory(threat);
            AnalyzeThreat(threat);
        }
    }
    
    return 0;
}

// System scan thread
DWORD WINAPI SystemScanThread(LPVOID lpParam) {
    UNREFERENCED_PARAMETER(lpParam);
    
    while (g_Running) {
        // In a real implementation, this would perform periodic system scans
        // For this example, we'll just scan once an hour
        
        std::this_thread::sleep_for(std::chrono::hours(1));
        
        if (!g_Running) {
            break;
        }
        
        ScanSystem();
    }
    
    return 0;
}

// Threat dialog procedure
INT_PTR CALLBACK ThreatDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    static THREAT_INFO* pThreat = NULL;
    
    switch (message) {
        case WM_INITDIALOG: {
            pThreat = (PTHREAT_INFO)lParam;
            
            // Set threat information
            SetDlgItemText(hDlg, IDC_THREAT_NAME, pThreat->ThreatName.c_str());
            SetDlgItemText(hDlg, IDC_THREAT_PATH, pThreat->FilePath.c_str());
            
            // Set threat level
            WCHAR levelText[50];
            switch (pThreat->ThreatLevel) {
                case THREAT_LEVEL_LOW:
                    wcscpy_s(levelText, L"Low");
                    break;
                case THREAT_LEVEL_MEDIUM:
                    wcscpy_s(levelText, L"Medium");
                    break;
                case THREAT_LEVEL_HIGH:
                    wcscpy_s(levelText, L"High");
                    break;
                case THREAT_LEVEL_CRITICAL:
                    wcscpy_s(levelText, L"Critical");
                    break;
            }
            SetDlgItemText(hDlg, IDC_THREAT_LEVEL, levelText);
            
            // Set description
            SetDlgItemText(hDlg, IDC_THREAT_DESCRIPTION, pThreat->Description.c_str());
            
            // Set recommendation
            SetDlgItemText(hDlg, IDC_THREAT_RECOMMENDATION, pThreat->Recommendation.c_str());
            
            // Center dialog
            RECT rcDlg, rcParent;
            GetWindowRect(hDlg, &rcDlg);
            GetWindowRect(GetParent(hDlg), &rcParent);
            
            int x = rcParent.left + (rcParent.right - rcParent.left - (rcDlg.right - rcDlg.left)) / 2;
            int y = rcParent.top + (rcParent.bottom - rcParent.top - (rcDlg.bottom - rcDlg.top)) / 2;
            
            SetWindowPos(hDlg, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
            
            return TRUE;
        }
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDC_SCAN_REMOVE:
                    HandleThreat(*pThreat, 0); // Remove
                    EndDialog(hDlg, IDOK);
                    break;
                    
                case IDC_SCAN_QUARANTINE:
                    HandleThreat(*pThreat, 1); // Quarantine
                    EndDialog(hDlg, IDOK);
                    break;
                    
                case IDC_SCAN_ALLOW:
                    HandleThreat(*pThreat, 2); // Allow
                    EndDialog(hDlg, IDOK);
                    break;
                    
                case IDC_THREAT_DETAILS:
                    // Show detailed information
                    MessageBox(hDlg, pThreat->Description.c_str(), L"Threat Details", MB_OK | MB_ICONINFORMATION);
                    break;
                    
                case IDCANCEL:
                    EndDialog(hDlg, IDCANCEL);
                    break;
            }
            break;
    }
    
    return FALSE;
}

// Settings dialog procedure
INT_PTR CALLBACK SettingsDialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    UNREFERENCED_PARAMETER(lParam);
    
    switch (message) {
        case WM_INITDIALOG:
            // Initialize settings controls
            CheckDlgButton(hDlg, IDC_REALTIME_PROTECTION, BST_CHECKED);
            CheckDlgButton(hDlg, IDC_AUTO_QUARANTINE, BST_CHECKED);
            CheckDlgButton(hDlg, IDC_BEHAVIOR_ANALYSIS, BST_CHECKED);
            CheckDlgButton(hDlg, IDC_RANSOMWARE_PROTECTION, BST_CHECKED);
            CheckDlgButton(hDlg, IDC_MEMORY_PROTECTION, BST_CHECKED);
            CheckDlgButton(hDlg, IDC_NETWORK_PROTECTION, BST_CHECKED);
            
            return TRUE;
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case IDOK:
                    // Save settings
                    EndDialog(hDlg, IDOK);
                    break;
                    
                case IDCANCEL:
                    EndDialog(hDlg, IDCANCEL);
                    break;
                    
                case IDC_UPDATE_SIGNATURES:
                    // Update signatures
                    UpdateSignatureDatabase();
                    MessageBox(hDlg, L"Signatures updated successfully.", L"Update Complete", MB_OK | MB_ICONINFORMATION);
                    break;
            }
            break;
    }
    
    return FALSE;
}

// Add to history
void AddToHistory(const THREAT_INFO& threat) {
    std::lock_guard<std::mutex> lock(g_ThreatMutex);
    g_ThreatHistory.push_back(threat);
    
    // Keep only the last 1000 threats
    if (g_ThreatHistory.size() > 1000) {
        g_ThreatHistory.erase(g_ThreatHistory.begin());
    }
}

// Refresh history list
void RefreshHistoryList() {
    HWND hList = GetDlgItem(g_hHistoryTab, IDC_HISTORY_LIST);
    if (!hList) {
        return;
    }
    
    // Clear list
    ListView_DeleteAllItems(hList);
    
    // Add items
    std::lock_guard<std::mutex> lock(g_ThreatMutex);
    
    for (const auto& threat : g_ThreatHistory) {
        LVITEM lvi;
        lvi.mask = LVIF_TEXT;
        lvi.iItem = ListView_GetItemCount(hList);
        lvi.iSubItem = 0;
        
        // Format time
        SYSTEMTIME st;
        FileTimeToSystemTime((FILETIME*)&threat.Timestamp, &st);
        
        WCHAR timeStr[100];
        swprintf_s(timeStr, L"%02d/%02d/%04d %02d:%02d:%02d", 
                  st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, st.wSecond);
        
        lvi.pszText = timeStr;
        ListView_InsertItem(hList, &lvi);
        
        // Threat name
        ListView_SetItemText(hList, lvi.iItem, 1, (LPWSTR)threat.ThreatName.c_str());
        
        // Threat level
        WCHAR levelStr[20];
        switch (threat.ThreatLevel) {
            case THREAT_LEVEL_LOW:
                wcscpy_s(levelStr, L"Low");
                break;
            case THREAT_LEVEL_MEDIUM:
                wcscpy_s(levelStr, L"Medium");
                break;
            case THREAT_LEVEL_HIGH:
                wcscpy_s(levelStr, L"High");
                break;
            case THREAT_LEVEL_CRITICAL:
                wcscpy_s(levelStr, L"Critical");
                break;
        }
        ListView_SetItemText(hList, lvi.iItem, 2, levelStr);
        
        // File/process
        ListView_SetItemText(hList, lvi.iItem, 3, (LPWSTR)(threat.FilePath.empty() ? threat.TargetProcess.c_str() : threat.FilePath.c_str()));
        
        // Action
        ListView_SetItemText(hList, lvi.iItem, 4, (LPWSTR)threat.Recommendation.c_str());
    }
}

// Refresh management list
void RefreshManagementList() {
    HWND hAllowList = GetDlgItem(g_hManagementTab, IDC_ALLOW_LIST);
    HWND hBlockList = GetDlgItem(g_hManagementTab, IDC_BLOCK_LIST);
    
    if (!hAllowList || !hBlockList) {
        return;
    }
    
    // Clear lists
    SendMessage(hAllowList, LB_RESETCONTENT, 0, 0);
    SendMessage(hBlockList, LB_RESETCONTENT, 0, 0);
    
    // Add items to allow list
    std::lock_guard<std::mutex> lock(g_ListMutex);
    
    for (const auto& item : g_AllowList) {
        SendMessage(hAllowList, LB_ADDSTRING, 0, (LPARAM)item.first.c_str());
    }
    
    // Add items to block list
    for (const auto& item : g_BlockList) {
        SendMessage(hBlockList, LB_ADDSTRING, 0, (LPARAM)item.first.c_str());
    }
}
