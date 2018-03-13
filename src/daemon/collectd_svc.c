#include "collectd.h"
#include <windows.h>
#include <tchar.h>

#undef __CRT__NO_INLINE
#include <strsafe.h>
#define __CRT__NO_INLINE

#define SVC_ERROR 1

SERVICE_STATUS gSvcStatus;
SERVICE_STATUS_HANDLE gSvcStatusHandle;

void WINAPI SvcCtrlHandler(DWORD);
void WINAPI SvcMain(DWORD, LPTSTR *);

void ReportSvcStatus(DWORD, DWORD, DWORD);
void SvcReportEvent(LPTSTR);

void __cdecl _tmain(int argc, TCHAR *argv[]) {
  SERVICE_TABLE_ENTRY DispatchTable[] = {
      {PACKAGE_NAME, (LPSERVICE_MAIN_FUNCTION)SvcMain}, {NULL, NULL}};

  if (!StartServiceCtrlDispatcher(DispatchTable)) {
    SvcReportEvent(TEXT("StartServiceCtrlDispatcher"));
  }
}

int init(int argc, char **argv) {
  WORD wVersionRequested;
  WSADATA wsaData;
  int err;
  wVersionRequested = MAKEWORD(2, 2);

  err = WSAStartup(wVersionRequested, &wsaData);
  if (err != 0) {
    printf("WSAStartup failed with error: %d\n", err);
    SvcReportEvent(TEXT("WSAStartup"));
    return 1;
  }
  
  struct cmdline_config config = init_config(argc, argv);
  return run_loop(config.test_readall);
}

void WINAPI SvcMain(DWORD dwArgc, LPTSTR *lpszArgv) {
  gSvcStatusHandle = RegisterServiceCtrlHandler(PACKAGE_NAME, SvcCtrlHandler);

  if (!gSvcStatusHandle) {
    SvcReportEvent(TEXT("RegisterServiceCtrlHandler"));
    return;
  }

  gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  gSvcStatus.dwServiceSpecificExitCode = 0;
  ReportSvcStatus(SERVICE_START_PENDING, NO_ERROR, 3000);
  ReportSvcStatus(SERVICE_RUNNING, NO_ERROR, 0);
  int err = init((int)dwArgc, (char**)lpszArgv);
  ReportSvcStatus(SERVICE_STOPPED, err, 0);
  return;
}

/**
 * Sets the current service status and reports it to the SCM.
 * dwCurrentState - The current state (see SERVICE_STATUS)
 * dwWin32ExitCode - The system error code
 * dwWaitHint - Estimated time for pending operation,
 *   in milliseconds
 */
void ReportSvcStatus(DWORD dwCurrentState, DWORD dwWin32ExitCode,
                     DWORD dwWaitHint) {
  static DWORD dwCheckPoint = 1;

  gSvcStatus.dwCurrentState = dwCurrentState;
  gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
  gSvcStatus.dwWaitHint = dwWaitHint;

  if (dwCurrentState == SERVICE_START_PENDING)
    gSvcStatus.dwControlsAccepted = 0;
  else
    gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

  if ((dwCurrentState == SERVICE_RUNNING) ||
      (dwCurrentState == SERVICE_STOPPED))
    gSvcStatus.dwCheckPoint = 0;
  else
    gSvcStatus.dwCheckPoint = dwCheckPoint++;

  SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

/**
 * Called by SCM whenever a control code is sent to the service
 *   using the ControlService function.
 * dwCtrl - control code
 */
void WINAPI SvcCtrlHandler(DWORD dwCtrl) {
  switch (dwCtrl) {
  case SERVICE_CONTROL_STOP:
    ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);
    stop_collectd();
    ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);
    return;
  case SERVICE_CONTROL_INTERROGATE:
    break;
  default:
    break;
  }
}

/**
 * Logs messages to the event log. The service must
 * have an entry in the Application event log.
 * szFunction - name of function that failed
 */
VOID SvcReportEvent(LPTSTR szFunction) {
  HANDLE hEventSource;
  LPCTSTR lpszStrings[2];
  TCHAR Buffer[80];

  hEventSource = RegisterEventSource(NULL, PACKAGE_NAME);

  if (NULL != hEventSource) {
    StringCchPrintf(Buffer, 80, TEXT("%s failed with %d"), szFunction,
                    GetLastError());

    lpszStrings[0] = PACKAGE_NAME;
    lpszStrings[1] = Buffer;

    ReportEvent(hEventSource,        // event log handle
                EVENTLOG_ERROR_TYPE, // event type
                0,                   // event category
                SVC_ERROR,           // event identifier
                NULL,                // no security identifier
                2,                   // size of lpszStrings array
                0,                   // no binary data
                lpszStrings,         // array of strings
                NULL);               // no binary data

    DeregisterEventSource(hEventSource);
  }
}