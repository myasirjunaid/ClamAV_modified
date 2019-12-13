#define _WIN32_IE 0x0500

#include <windows.h>
#include <dbt.h>
#include <direct.h>
#include <stdio.h>
#include <shlwapi.h>

#include "USBVirusScan.h"

#define USBVIRUSSCAN "USBVirusScan"
#define USBVIRUSSCANCLASS "USBVirusScanClass"
#define VERSION "1.7.5"
#define USBVIRUSSCANMUTEX "Local\\USBVirusScanMutex"

#define SWM_TRAYMSG	WM_APP
#define SWM_ABOUT		WM_APP + 1//	about
#define SWM_EXIT		WM_APP + 2//	exit the program

#define TRAY_ICON_ID	2110;

char szScanCommand[1024];
char szAbout[1024];
int iFlagHideConsole;
int iFlagHideIcon;
int iFlagDisableExit;
int iFlagQuit;
int iFlagDebug;
int iFlagStartupScan;
int iFlagRemovalScan;
int iFlagDisableWow64FsRedirection;
int iFlagBanner;
int iCountBannerDisplays;

// Function prototype
LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
char FirstDriveFromMask(ULONG unitmask);
void TrayIconAdd(HWND, HINSTANCE);
void TrayIconBalloon(HWND, char *, char *, UINT, DWORD);
void TrayIconDelete(HWND);
void ShowContextMenu(HWND);
void MakeCommand(char *, int, char *, char, DWORD, char *, char *, char);
char *AddChr(char *, int, char, int *);
char *AddStr(char *, int, char *, int *);
int IsInstanceRunning(void);
int StopRunningInstance(void);
void Usage(void);
void ProcessDrive(char, HWND, char);
void ScanAtStarup(HWND);

#define countof(array)	(sizeof(array) / sizeof(array[0]))

void OutputDebugStringPrefix(LPTSTR pszMessage)
{
	TCHAR szOutput[256];

	_sntprintf(szOutput, countof(szOutput), TEXT("[UVS] %s"), pszMessage);
	OutputDebugString(szOutput);
}

void OutputDebugStringPrefixF(LPTSTR pszFormat, ...)
{
	TCHAR szOutput[256];
	va_list vaArgs;

	va_start(vaArgs, pszFormat);
	_vsntprintf(szOutput, countof(szOutput), pszFormat, vaArgs);
	OutputDebugStringPrefix(szOutput);
	va_end(vaArgs);
}

void OutputErrorMessage(LPTSTR pszMessage, DWORD dwLastError)
{
	HLOCAL hlErrorMessage = NULL;
	if (FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER, NULL, dwLastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), (PTSTR) &hlErrorMessage, 0, NULL))
	{
		OutputDebugStringPrefixF(TEXT("%s: %s"), pszMessage, (PCTSTR) LocalLock(hlErrorMessage));
		LocalFree(hlErrorMessage);
	}
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nCmdShow)
{
	MSG					msg;					// MSG structure to store messages
	HWND				hwndMain;			// Main window handle
	WNDCLASSEX	wcx;					// WINDOW class information	
	HDEVNOTIFY	hDevnotify;
	DEV_BROADCAST_DEVICEINTERFACE NotificationFilter;
	char *pchIter;
	int iParseState;

	GUID FilterGUID = {0x2121fde7, 0x4050, 0x4ecf, {0x90, 0x90, 0xd9, 0xc3, 0x57, 0xb1, 0xca, 0xf7}};    		
	
	sprintf(szAbout, "%s v%s %s", USBVIRUSSCAN, VERSION, URL);
	
	// Get command line
	if (lpCmdLine[0] == '\0') {
		Usage();
		return 0;
	}
	else
	{
		pchIter = lpCmdLine;
		iParseState = 0;
		iFlagHideIcon = 0;
		iFlagHideConsole = 0;
		iFlagDisableExit = 0;
		iFlagStartupScan = 0;
		iFlagRemovalScan = 0;
		iFlagDisableWow64FsRedirection = 0;
		iFlagBanner = 0;
		iCountBannerDisplays = 0;
		do {
			if (*pchIter == ' ')
			{
				iParseState = 0;
			}
			else if (*pchIter == '-' && iParseState == 0)
			{
				iParseState = 1;
			}
			else if (*pchIter == 'i' && (iParseState == 1 || iParseState == 2))
			{
				iParseState = 2;
				iFlagHideIcon = 1;
			}
			else if (*pchIter == 'c' && (iParseState == 1 || iParseState == 2))
			{
				iParseState = 2;
				iFlagHideConsole = 1;
			}
			else if (*pchIter == 'e' && (iParseState == 1 || iParseState == 2))
			{
				iParseState = 2;
				iFlagDisableExit = 1;
			}
			else if (*pchIter == 'q' && (iParseState == 1 || iParseState == 2))
			{
				iParseState = 2;
				iFlagQuit = 1;
			}
			else if (*pchIter == 'd' && (iParseState == 1 || iParseState == 2))
			{
				iParseState = 2;
				iFlagDebug = 1;
			}
			else if (*pchIter == 's' && (iParseState == 1 || iParseState == 2))
			{
				iParseState = 2;
				iFlagStartupScan = 1;
			}
			else if (*pchIter == 'r' && (iParseState == 1 || iParseState == 2))
			{
				iParseState = 2;
				iFlagRemovalScan = 1;
			}
			else if (*pchIter == 'w' && (iParseState == 1 || iParseState == 2))
			{
				iParseState = 2;
				iFlagDisableWow64FsRedirection = 1;
			}
			else if (*pchIter == 'b' && (iParseState == 1 || iParseState == 2))
			{
				iParseState = 2;
				iFlagBanner = 1;
			}
			else if (*pchIter == 'B' && (iParseState == 1 || iParseState == 2))
			{
				iParseState = 2;
				iFlagBanner = 2;
			}
			else if (iParseState == 1 || iParseState == 2)
			{
				Usage();
				return 0;
			} else
				break;
		} while (*++pchIter != '\0');
		if (*pchIter != '\0')
			strncpy(szScanCommand, pchIter, 1024);
	}

	// option -q cannot be used with other options
	if (iFlagQuit && (iFlagHideConsole || iFlagHideIcon || iFlagDisableExit || iFlagStartupScan ||iFlagRemovalScan || *szScanCommand != '\0'))
	{
		Usage();
		return 0;
	}

	// Stop the other running instance if -q option
	if (iFlagQuit && IsInstanceRunning())
	{
		StopRunningInstance();
		return 0;
	}
	
	// Only one instance of the program must be running
	if (IsInstanceRunning())
		return 0;
		
	// Initialize the struct to zero
	ZeroMemory(&wcx, sizeof(wcx));
	
	wcx.cbSize = sizeof(wcx);								// Window size. Must always be sizeof(WNDCLASSEX)
	wcx.style = 0 ;													// Class styles
	wcx.lpfnWndProc = (WNDPROC)MainWndProc; // Pointer to the callback procedure
	wcx.cbClsExtra = 0;											// Extra byte to allocate following the wndclassex structure
	wcx.cbWndExtra = 0;											// Extra byte to allocate following an instance of the structure
	wcx.hInstance = hInstance;							// Instance of the application
	wcx.hIcon = NULL;												// Class Icon
	wcx.hCursor = NULL;											// Class Cursor
	wcx.hbrBackground = NULL;								// Background brush
	wcx.lpszMenuName = NULL;								// Menu resource
	wcx.lpszClassName = USBVIRUSSCANCLASS;	// Name of this class
	wcx.hIconSm = NULL;											// Small icon for this class

	// Register this window class with MS-Windows
	if (!RegisterClassEx(&wcx))
		return 0;

	// Create the window
	hwndMain = CreateWindowEx(0,									// Extended window style
														USBVIRUSSCANCLASS,	// Window class name
														"",									// Window title
														WS_POPUP,						// Window style
														0,0,								// (x,y) pos of the window
														0,0,								// Width and height of the window
														NULL,								// HWND of the parent window (can be null also)
														NULL,								// Handle to menu
														hInstance,					// Handle to application instance
														NULL);							// Pointer to window creation data

	// Check if window creation was successful
	if (!hwndMain)
		return 0;

	// Make the window invisible
	ShowWindow(hwndMain, SW_HIDE);

	// Initialize device class structure 
	ZeroMemory(&NotificationFilter, sizeof(NotificationFilter));

	NotificationFilter.dbcc_size = 0x20;
	NotificationFilter.dbcc_devicetype = 5;			// DBT_DEVTYP_DEVICEINTERFACE;
	NotificationFilter.dbcc_classguid = FilterGUID;
		
	// Register
	hDevnotify = RegisterDeviceNotification(hwndMain, &NotificationFilter, DEVICE_NOTIFY_WINDOW_HANDLE);

	if(hDevnotify == NULL)    
		return 0;

	if (!iFlagHideIcon)
		TrayIconAdd(hwndMain, hInstance);

	// scan available removable drives
	if (iFlagStartupScan)
		ScanAtStarup(hwndMain);
	
	// Process messages coming to this window
	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	// return value to the system
	return msg.wParam;
}

typedef BOOL (WINAPI *tpfWow64DisableWow64FsRedirection) (PVOID *OldValue );
typedef BOOL (WINAPI *tpfWow64RevertWow64FsRedirection) (PVOID OldValue );

ULONG WINAPI DisplayBanner(LPVOID parameter)
{
	HANDLE hFile;
	DWORD dwFileSize;
	DWORD dwBytesRead;
	CHAR *szBanner;
	
	hFile = CreateFile("banner.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
	if (NULL == hFile)
		return -1;
	dwFileSize = GetFileSize(hFile, NULL);
	if (INVALID_FILE_SIZE == dwFileSize)
	{
		CloseHandle(hFile);
		return -2;
	}
	szBanner = (CHAR *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwFileSize + 1);
	if (NULL == szBanner)
	{
		CloseHandle(hFile);
		return -3;
	}
	if (!ReadFile(hFile, szBanner, dwFileSize, &dwBytesRead, NULL))
	{
		CloseHandle(hFile);
		return -4;
	}
	CloseHandle(hFile);
	MessageBox(NULL, szBanner, "USBVirusScan", MB_OK | MB_SYSTEMMODAL);
	HeapFree(GetProcessHeap(), 0, szBanner);
	iCountBannerDisplays++;
	return 0;
}

void ProcessDrive(char chDrive, HWND hwnd, char chAction)
{
	char szBuffer[1024];
	char szBalloon[1024];
	STARTUPINFO s;
	PROCESS_INFORMATION p;
	char szVolumeNameBuffer[1024];
	DWORD dwVolumeSerialNumber;
	DWORD dwMaximumComponentLength;
	DWORD dwFileSystemFlags;
	char szFileSystemNameBuffer[1024];
	tpfWow64DisableWow64FsRedirection pfWow64DisableWow64FsRedirection;
	tpfWow64RevertWow64FsRedirection pfWow64RevertWow64FsRedirection;
	PVOID pvOldValue;

	sprintf(szBuffer, "%c:\\", chDrive);
	GetVolumeInformation(szBuffer, szVolumeNameBuffer, 1024, &dwVolumeSerialNumber, &dwMaximumComponentLength, &dwFileSystemFlags, szFileSystemNameBuffer, 1024);

	if (!iFlagHideIcon)
	{
		sprintf(szBalloon, "Drive %c: inserted.\nVolume name: %s\nSerial number: %08lX\nFilesystem: %s", chDrive, szVolumeNameBuffer, dwVolumeSerialNumber, szFileSystemNameBuffer);
		TrayIconBalloon(hwnd, szBalloon, USBVIRUSSCAN, 5, NIIF_WARNING);
		if (iFlagDebug)
		{
			OutputDebugStringPrefixF("Your is Being Scanned", chDrive);
			OutputDebugStringPrefixF("Drive %c: inserted.", chDrive);
			OutputDebugStringPrefixF("Volume name: %s", szVolumeNameBuffer);
			OutputDebugStringPrefixF("Serial number: %08lX", dwVolumeSerialNumber);
			OutputDebugStringPrefixF("Filesystem: %s", szFileSystemNameBuffer);
		}
	}

	if (iFlagDebug)
		OutputDebugStringPrefix(szScanCommand);
	MakeCommand(szBuffer, 1024, szScanCommand, chDrive, dwVolumeSerialNumber, szVolumeNameBuffer, szFileSystemNameBuffer, chAction);
	
	ZeroMemory(&s, sizeof(s));
	s.cb = sizeof(s);
	ZeroMemory(&p, sizeof(p));
	if (iFlagDebug)
		OutputDebugStringPrefix(szBuffer);
	if (iFlagDisableWow64FsRedirection)
	{
		pfWow64DisableWow64FsRedirection = (tpfWow64DisableWow64FsRedirection) GetProcAddress(GetModuleHandle("kernel32"), "Wow64DisableWow64FsRedirection");
		pfWow64RevertWow64FsRedirection = (tpfWow64RevertWow64FsRedirection) GetProcAddress(GetModuleHandle("kernel32"), "Wow64RevertWow64FsRedirection");
		if (NULL == pfWow64DisableWow64FsRedirection || NULL == pfWow64RevertWow64FsRedirection)
		{
			if (iFlagDebug)
				OutputDebugStringPrefix("WOW64 filesystem redirection functions not found");
		}
		else
			pfWow64DisableWow64FsRedirection(&pvOldValue);
	}
	if (CreateProcess(NULL, szBuffer, NULL, NULL, FALSE, iFlagHideConsole ? CREATE_NO_WINDOW : CREATE_NEW_CONSOLE, NULL, NULL, &s, &p))
	{
		if (iFlagDebug)
			OutputDebugStringPrefixF("Process created, process ID = %d", p.dwProcessId);
		CloseHandle(p.hProcess);
		CloseHandle(p.hThread);
	}
	else
	{
		if (iFlagDebug)
			OutputErrorMessage("Process creation failed", GetLastError());
	}
	if (iFlagDisableWow64FsRedirection && NULL != pfWow64RevertWow64FsRedirection)
		pfWow64RevertWow64FsRedirection(pvOldValue);

	if (2 == iFlagBanner || 1 == iFlagBanner && 0 == iCountBannerDisplays)
	{
		CreateThread(NULL, 0, DisplayBanner, &hwnd, 0, NULL);
	}
}


#define IOCTL_STORAGE_QUERY_PROPERTY CTL_CODE(IOCTL_STORAGE_BASE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)

// retrieve the storage device descriptor data for a device. 
typedef struct _STORAGE_DEVICE_DESCRIPTOR
{
	ULONG Version;
	ULONG Size;
	UCHAR DeviceType;
	UCHAR DeviceTypeModifier;
	BOOLEAN RemovableMedia;
	BOOLEAN CommandQueueing;
	ULONG VendorIdOffset;
	ULONG ProductIdOffset;
	ULONG ProductRevisionOffset;
	ULONG SerialNumberOffset;
	STORAGE_BUS_TYPE BusType;
	ULONG RawPropertiesLength;
	UCHAR RawDeviceProperties[1];
} STORAGE_DEVICE_DESCRIPTOR, *PSTORAGE_DEVICE_DESCRIPTOR;

// retrieve the properties of a storage device or adapter. 
typedef enum _STORAGE_QUERY_TYPE 
{
	PropertyStandardQuery = 0,
	PropertyExistsQuery,
	PropertyMaskQuery,
	PropertyQueryMaxDefined,
	PropertyQueryDummy = 0xFFFFFFFF
} STORAGE_QUERY_TYPE, *PSTORAGE_QUERY_TYPE;

// retrieve the properties of a storage device or adapter. 
typedef enum _STORAGE_PROPERTY_ID
{
	StorageDeviceProperty = 0,
	StorageAdapterProperty,
	StorageDeviceIdProperty,
	StorageDummy = 0xFFFFFFFF
} STORAGE_PROPERTY_ID, *PSTORAGE_PROPERTY_ID;

// retrieve the properties of a storage device or adapter. 
#pragma pack(push, 4)
typedef struct _STORAGE_PROPERTY_QUERY
{
	STORAGE_PROPERTY_ID PropertyId;
	STORAGE_QUERY_TYPE QueryType;
	UCHAR AdditionalParameters[1];
} STORAGE_PROPERTY_QUERY, *PSTORAGE_PROPERTY_QUERY;
#pragma pack(pop)

BOOL GetDisksProperty(HANDLE hDevice, PSTORAGE_DEVICE_DESCRIPTOR pDevDesc)
{
	STORAGE_PROPERTY_QUERY Query;
	DWORD dwOutBytes;
	BOOL bResult;
	
	// specify the query type
	Query.PropertyId = StorageDeviceProperty;
	Query.QueryType = PropertyStandardQuery;
	
	// Query using IOCTL_STORAGE_QUERY_PROPERTY 
	bResult = DeviceIoControl(hDevice,	IOCTL_STORAGE_QUERY_PROPERTY,	&Query, sizeof(Query), pDevDesc, pDevDesc->Size, &dwOutBytes,	(LPOVERLAPPED)NULL);
	
	return bResult;
}

void ScanAtStarup(HWND hwnd)
{
	ULONG unitmask;
	char chDrive;
	char szDrive[10];
	UINT uiDriveType;
	HANDLE hDevice;
	BYTE abDevDesc[sizeof(STORAGE_DEVICE_DESCRIPTOR) + 512 - 1];
	PSTORAGE_DEVICE_DESCRIPTOR pDevDesc;
	
	unitmask = GetLogicalDrives() >> 2;
	for (chDrive = 'C'; chDrive <= 'Z'; chDrive++)
	{
		if (unitmask & 1)
		{
			snprintf(szDrive, 9, "%c:\\", chDrive);
			szDrive[9] = '\0';
			uiDriveType = GetDriveType(szDrive);
			switch (uiDriveType)
			{
				case DRIVE_REMOVABLE:
					ProcessDrive(chDrive, hwnd, 'A');
					break;

				case DRIVE_FIXED:
					snprintf(szDrive, 9, "\\\\.\\%c:", chDrive);
					szDrive[9] = '\0';
					hDevice = CreateFile(szDrive, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);

					if (hDevice != INVALID_HANDLE_VALUE)
					{
						pDevDesc = (PSTORAGE_DEVICE_DESCRIPTOR) &abDevDesc;
						pDevDesc->Size = sizeof(abDevDesc);

						if(GetDisksProperty(hDevice, pDevDesc))
							if(pDevDesc->BusType == BusTypeUsb)
								ProcessDrive(chDrive, hwnd, 'A');

						CloseHandle(hDevice);
					}
					break;
			}
		}
		unitmask = unitmask >> 1;
	}
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	char chDrive;
	PDEV_BROADCAST_VOLUME PdevVolume;
	PDEV_BROADCAST_DEVICEINTERFACE PdevDEVICEINTERFACE;

	switch (msg)
	{
		case WM_DEVICECHANGE:
			if (wParam == DBT_DEVICEARRIVAL || (iFlagRemovalScan && (wParam == DBT_DEVICEREMOVECOMPLETE)))
			{
				// A device or piece of media has been inserted and is now available
				PdevDEVICEINTERFACE = (PDEV_BROADCAST_DEVICEINTERFACE)lParam;
				if (PdevDEVICEINTERFACE->dbcc_devicetype == DBT_DEVTYP_VOLUME)
				{
					PdevVolume = (PDEV_BROADCAST_VOLUME)lParam;
					chDrive = FirstDriveFromMask(PdevVolume->dbcv_unitmask);
					if (chDrive != '\0' && !(PdevVolume->dbcv_flags & DBTF_NET)) 
						ProcessDrive(chDrive, hwnd, wParam == DBT_DEVICEARRIVAL ? 'A' : 'R');
				}
			}
			break;

		case WM_COMMAND:
			switch (LOWORD(wParam))
			{
				case SWM_EXIT:
					DestroyWindow(hwnd);
					break;
				case SWM_ABOUT:
					MessageBox(hwnd,
											"USBVirusScan starts an AV-scan when a USB stick is inserted.\n\n"
											"It requires the AV-scan command as command-line argument.\n"
											"Usage: USBVirusScan [-ciesrqdwbB] command\n"
											"-c hides the command window\n"
											"-i hides the tray icon\n"
											"-e disables the Exit menu option\n"
											"-s scan available removable drives at program start\n"
											"-r also start program at drive removal\n"
											"-q stops the running instance of USBVirusScan from the command-line\n"
											"-d outputs debug messages, use a tool like DebugView to view the messages\n"
											"-w disable WOW64 filesystem redirection\n"
											"-b display content of banner.txt the first time a removable drive is connected\n"
											"-B display content of banner.txt each time a removable drive is connected\n"
											"%d in the command stands for the drive letter, %v for the volume name (can be empty), %s for the volume serial number, %f for the filesystem type and %e for the event type (A for arrival and R for removal)\n"
											"Example for McAfee VirusScan Enterprise 8.0i:\n"
											" USBVirusScan \"c:\\Program Files\\Network Associates\\VirusScan\\csscan.exe\" /target %d: /secure /quit /log c:\\USBvirusscan.log\n"
											"Of course, you can provide any command, not just starting an AV-scan.",
											szAbout,
											MB_OK);
					break;
			}
			return 1;
	
		case WM_DESTROY:
			if (!iFlagHideIcon)
				TrayIconDelete(hwnd);
			PostQuitMessage(0);
			break;

		case SWM_TRAYMSG:
			switch(lParam)
			{
				case WM_LBUTTONDBLCLK:
					break;
				case WM_RBUTTONDOWN:
				case WM_CONTEXTMENU:
					ShowContextMenu(hwnd);
			}
				
		default:
			// Call the default window handler
			return DefWindowProc(hwnd, msg, wParam, lParam);
	}

	return 0;
}

char FirstDriveFromMask(ULONG unitmask)
{
	char chIter;
	
	for (chIter = 'A'; chIter <= 'Z'; chIter++)
		if (unitmask & 0x1)
			return chIter;
		else
			unitmask = unitmask >> 1;
	
	return '\0';
}

void TrayIconAdd(HWND hwnd, HINSTANCE hInstance)
{
	NOTIFYICONDATA nid;
	char szTip[1024];

	ZeroMemory(&nid, sizeof(NOTIFYICONDATA));
	nid.cbSize = sizeof(NOTIFYICONDATA);
	nid.uID = TRAY_ICON_ID;
	nid.uFlags = NIF_ICON|NIF_MESSAGE|NIF_TIP;
	nid.hIcon = (HICON)LoadImage(hInstance, MAKEINTRESOURCE(IDI_MY_ICON), IMAGE_ICON, GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), LR_DEFAULTCOLOR);
	nid.hWnd = hwnd;
	nid.uCallbackMessage = SWM_TRAYMSG;
	sprintf(szTip, "%s v%s", USBVIRUSSCAN, VERSION);
	strcpy(nid.szTip, szTip);
	Shell_NotifyIcon(NIM_ADD, &nid);
	if (nid.hIcon && DestroyIcon(nid.hIcon))
		nid.hIcon = NULL;
}

void TrayIconBalloon(HWND hwnd, char *szMessage, char *szTitle, UINT uTimeout, DWORD dwInfoFlags)
{
	NOTIFYICONDATA nid;

	ZeroMemory(&nid, sizeof(NOTIFYICONDATA));
	nid.cbSize = sizeof(NOTIFYICONDATA);
	nid.uID = TRAY_ICON_ID;
	nid.uFlags = NIF_INFO;
	nid.hWnd = hwnd;
	nid.DUMMYUNIONNAME.uTimeout = uTimeout;
	nid.dwInfoFlags = dwInfoFlags;
	strcpy(nid.szInfo, _T(szMessage));
	strcpy(nid.szInfoTitle, _T(szTitle));
	Shell_NotifyIcon(NIM_MODIFY, &nid);
}

void TrayIconDelete(HWND hwnd)
{
	NOTIFYICONDATA nid;

	ZeroMemory(&nid, sizeof(NOTIFYICONDATA));
	nid.cbSize = sizeof(NOTIFYICONDATA);
	nid.uID = TRAY_ICON_ID;
	nid.hWnd = hwnd;
	Shell_NotifyIcon(NIM_DELETE, &nid);
}

void ShowContextMenu(HWND hWnd)
{
	POINT pt;
	HMENU hMenu;
	
	GetCursorPos(&pt);
	hMenu = CreatePopupMenu();
	if (hMenu)
	{
		InsertMenu(hMenu, -1, MF_BYPOSITION, SWM_ABOUT, _T("About"));
		InsertMenu(hMenu, -1, iFlagDisableExit ? MF_BYPOSITION|MF_GRAYED : MF_BYPOSITION, SWM_EXIT, _T("Exit"));
		// note:	must set window to the foreground or the
		//			menu won't disappear when it should
		SetForegroundWindow(hWnd);
		TrackPopupMenu(hMenu, TPM_BOTTOMALIGN, pt.x, pt.y, 0, hWnd, NULL );
		DestroyMenu(hMenu);
	}
}

// Substitute %d, %c with chDrive, %v with szVolumeNameBuffer, %s with dwVolumeSerialNumber, %f with szFileSystemNameBuffer and %e with chAction
void MakeCommand(char *szBuffer, int iBufferSize, char *szScanCommand, char chDrive, DWORD dwVolumeSerialNumber, char *szVolumeNameBuffer, char *szFileSystemNameBuffer, char chAction)
{
	char szSerial[1024];
	char *pchIterBuffer;
	char *pchIterScanCommand;
	int iBufferStrLen;

	ZeroMemory(szBuffer, iBufferSize);
	pchIterBuffer = szBuffer;
	pchIterScanCommand = szScanCommand;
	iBufferStrLen = 0;
	while (*pchIterScanCommand != '\0')
	{
		if (*pchIterScanCommand == '%')
		{
			switch (*++pchIterScanCommand)
			{
				case 'c':
				case 'C':
				case 'd':
				case 'D':
					if ((pchIterBuffer = AddChr(pchIterBuffer, iBufferSize, chDrive, &iBufferStrLen)) == NULL)
						return;
					break;
					
				case 's':
				case 'S':
					sprintf(szSerial, "%08lX", dwVolumeSerialNumber);
					if ((pchIterBuffer = AddStr(pchIterBuffer, iBufferSize, szSerial, &iBufferStrLen)) == NULL)
						return;
					break;
					
				case 'v':
				case 'V':
					if ((pchIterBuffer = AddStr(pchIterBuffer, iBufferSize, szVolumeNameBuffer, &iBufferStrLen)) == NULL)
						return;
					break;
					
				case 'f':
				case 'F':
					if ((pchIterBuffer = AddStr(pchIterBuffer, iBufferSize, szFileSystemNameBuffer, &iBufferStrLen)) == NULL)
						return;
					break;
					
				case 'e':
				case 'E':
					if ((pchIterBuffer = AddChr(pchIterBuffer, iBufferSize, chAction, &iBufferStrLen)) == NULL)
						return;
					break;
					
				default:
					if ((pchIterBuffer = AddChr(pchIterBuffer, iBufferSize, '%', &iBufferStrLen)) == NULL)
						return;
					if ((pchIterBuffer = AddChr(pchIterBuffer, iBufferSize, *pchIterScanCommand, &iBufferStrLen)) == NULL)
						return;
			}
			pchIterScanCommand++;
		}
		else
			if ((pchIterBuffer = AddChr(pchIterBuffer, iBufferSize, *pchIterScanCommand++, &iBufferStrLen)) == NULL)
				return;
	}
}

char *AddChr(char *pchBuffer, int iBufferSize, char chToAdd, int *piBufferStrLen)
{
	if (*piBufferStrLen >= iBufferSize - 2)
		return NULL;
	*pchBuffer = chToAdd;
	(*piBufferStrLen)++;
	return pchBuffer + 1;
}

char *AddStr(char *pchBuffer, int iBufferSize, char *pchToAdd, int *piBufferStrLen)
{
	while (*pchToAdd != '\0')
		if ((pchBuffer = AddChr(pchBuffer, iBufferSize, *pchToAdd++, piBufferStrLen)) == NULL)
			return NULL;
	return pchBuffer;
}

// Create a Mutex, to check if another instance is running
int IsInstanceRunning(void)
{
	CreateMutex(NULL, TRUE, USBVIRUSSCANMUTEX);
	return GetLastError() == ERROR_ALREADY_EXISTS;
}

// Stop another running instance
int StopRunningInstance(void)
{
	HWND hwndUSBVirusScan;
	
	if ((hwndUSBVirusScan = FindWindow(USBVIRUSSCANCLASS, "")) == NULL)
		return 0;
	SendNotifyMessage(hwndUSBVirusScan, WM_DESTROY, 0, 0);
	
	return 1;
}

// Display usage messagebox
void Usage(void)
{
	MessageBox(NULL,
							"USBVirusScan requires the AV-scan command as command-line argument.\n\n"
							"Usage: USBVirusScan [-ciesrqdwbB] command\n"
							"-c hides the command window\n"
							"-i hides the tray icon\n"
							"-e disables the Exit menu option\n"
							"-s scan available removable drives at program start\n"
							"-r also start program at drive removal\n"
							"-q stops the running instance of USBVirusScan from the command-line\n"
							"-d outputs debug messages, use a tool like DebugView to view the messages\n"
							"-w disable WOW64 filesystem redirection\n"
							"-b display content of banner.txt the first time a removable drive is connected\n"
							"-B display content of banner.txt each time a removable drive is connected\n"
							"%d in the command stands for the drive letter, %v for the volume name (can be empty), %s for the volume serial number, %f for the filesystem type and %e for the event type (A for arrival and R for removal)\n"
							"Example for McAfee VirusScan Enterprise 8.0i:\n"
							" USBVirusScan \"c:\\Program Files\\Network Associates\\VirusScan\\csscan.exe\" /target %d: /secure /quit /log c:\\USBvirusscan.log",
							szAbout,
							MB_OK);
}
