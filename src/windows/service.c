/*
 * Copyright (c) 2020, NLNet Labs, Sinodun
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 * * Neither the names of the copyright holders nor the
 *   names of its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Verisign, Inc. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdio.h>

#include <windows.h>
#include <tchar.h>
#include <strsafe.h>

#include "service.h"

void winerr(const TCHAR* operation)
{
        char msg[512];
        DWORD err = GetLastError();

        if ( FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
                           NULL,
                           err,
                           0,
                           msg,
                           sizeof(msg),
                           NULL) == 0 )
                fprintf(stderr, "%s: errno=%d\n", operation, err);
        else
                fprintf(stderr, "%s: %s\n", operation, msg);
        exit(1);
}


// #pragma comment(lib, "advapi32.lib")

#define SVCNAME TEXT("Stubby")

SERVICE_STATUS          gSvcStatus;
SERVICE_STATUS_HANDLE   gSvcStatusHandle;
HANDLE                  ghSvcStopEvent = NULL;

VOID SvcInstall(void);
VOID SvcRemove(void);
VOID SvcService(void);
VOID SvcStart(void);
VOID SvcStop(void);
VOID WINAPI SvcCtrlHandler( DWORD );
VOID WINAPI SvcMain( DWORD, LPTSTR * );

VOID ReportSvcStatus( DWORD, DWORD, DWORD );
VOID SvcInit( DWORD, LPTSTR * );
VOID SvcReportEvent( LPTSTR );


void WinServiceCommand(const TCHAR* arg)
{
        if ( lstrcmpi(arg, TEXT("install")) == 0 )
                SvcInstall();
        else if ( lstrcmpi(arg, TEXT("remove")) == 0 )
                SvcRemove();
        else if ( lstrcmpi(arg, TEXT("service")) == 0 )
                SvcService();
        else if ( lstrcmpi(arg, TEXT("start")) == 0 )
                SvcStart();
        else if ( lstrcmpi(arg, TEXT("stop")) == 0 )
                SvcStop();
        else
        {
                fprintf(stderr, "Unknown Windows option '%s'\n", arg);
                exit(1);
        }

        exit(0);
}

VOID SvcService()
{
        SERVICE_TABLE_ENTRY DispatchTable[] = {
                { SVCNAME, (LPSERVICE_MAIN_FUNCTION) SvcMain },
                { NULL, NULL }
        };

        // This call returns when the service has stopped.
        // The process should simply terminate when the call returns.
        if ( !StartServiceCtrlDispatcher(DispatchTable) )
        {
                SvcReportEvent(TEXT("StartServiceCtrlDispatcher"));
        }
}

static void createRegistryEntries(const TCHAR* path)
{
        TCHAR buf[512];
        HKEY hkey;
        DWORD t;
        snprintf(buf, sizeof(buf), "SYSTEM\\CurrentControlSet\\Services"
                 "\\EventLog\\Application\\%s", SVCNAME);
        if ( RegCreateKeyEx(
                     HKEY_LOCAL_MACHINE,
                     buf,       // Key
                     0,         // Reserved
                     NULL,      // Class
                     REG_OPTION_NON_VOLATILE, // Info on file
                     KEY_WRITE, // Access rights
                     NULL,      // Security descriptor
                     &hkey,     // Result
                     NULL       // Don't care if it exists
                     ) != ERROR_SUCCESS )
                winerr("Create registry key");

        if ( RegSetValueEx(
                     hkey,                      // Key handle
                     "EventMessageFile",        // Value name
                     0,                         // Reserved
                     REG_EXPAND_SZ,             // It's a string
                     (const BYTE*) path,        // with this value
                     strlen(path) + 1           // and this long
                     ) != ERROR_SUCCESS )
        {
                RegCloseKey(hkey);
                winerr("Set EventMessageFile");
        }

        if ( RegSetValueEx(
                     hkey,                      // Key handle
                     "CategoryMessageFile",     // Value name
                     0,                         // Reserved
                     REG_EXPAND_SZ,             // It's a string
                     (const BYTE*) path,        // with this value
                     strlen(path) + 1           // and this long
                     ) != ERROR_SUCCESS )
        {
                RegCloseKey(hkey);
                winerr("Set CategoryMessageFile");
        }

        /* event types */
        t = EVENTLOG_ERROR_TYPE | EVENTLOG_WARNING_TYPE | EVENTLOG_INFORMATION_TYPE;
        if ( RegSetValueEx(
                     hkey,                      // Key handle
                     "TypesSupported",          // Value name
                     0,                         // Reserved
                     REG_DWORD,                 // It's a DWORD
                     (const BYTE*) &t,          // with this value
                     sizeof(t)                  // and this long
                     ) != ERROR_SUCCESS )
        {
                RegCloseKey(hkey);
                winerr("Set TypesSupported");
        }

        t = 1;
        if ( RegSetValueEx(
                     hkey,                      // Key handle
                     "CategoryCount",           // Value name
                     0,                         // Reserved
                     REG_DWORD,                 // It's a DWORD
                     (const BYTE*) &t,          // with this value
                     sizeof(t)                  // and this long
                     ) != ERROR_SUCCESS )
        {
                RegCloseKey(hkey);
                winerr("Set TypesSupported");
        }
        RegCloseKey(hkey);
}

static void deleteRegistryEntries(void)
{
        HKEY hkey;
        DWORD t;

        if ( RegCreateKeyEx(
                     HKEY_LOCAL_MACHINE,
                     "SYSTEM\\CurrentControlSet\\Services"
                     "\\EventLog\\Application",
                     0,         // Reserved
                     NULL,      // Class
                     REG_OPTION_NON_VOLATILE, // Info on file
                     DELETE,    // Access rights
                     NULL,      // Security descriptor
                     &hkey,     // Result
                     NULL       // Don't care if it exists
                     ) != ERROR_SUCCESS )
                winerr("Create registry key");

        if ( RegDeleteKey(
                     hkey,
                     SVCNAME
                     ) != ERROR_SUCCESS )
        {
                RegCloseKey(hkey);
                winerr("Delete registry key");
        }
        RegCloseKey(hkey);
}

VOID SvcInstall()
{
        SC_HANDLE schSCManager;
        SC_HANDLE schService;
        TCHAR modpath[MAX_PATH];
        const TCHAR ARG[] = "-w service";
        TCHAR cmd[MAX_PATH + 3 + sizeof(ARG)];

        if( !GetModuleFileName(NULL, modpath, MAX_PATH) )
                winerr("GetModuleFileName");
        snprintf(cmd, sizeof(cmd), "\"%s\" %s", modpath, ARG);

        createRegistryEntries(modpath);

        schSCManager = OpenSCManager(
                NULL,                    // local computer
                NULL,                    // ServicesActive database
                SC_MANAGER_ALL_ACCESS);  // full access rights

        if (NULL == schSCManager)
                winerr("Open service manager");

        schService = CreateService(
                schSCManager,              // SCM database
                SVCNAME,                   // name of service
                "Stubby secure DNS proxy", // service name to display
                SERVICE_ALL_ACCESS,        // desired access
                SERVICE_WIN32_OWN_PROCESS, // service type
                SERVICE_DEMAND_START,      // start type
                SERVICE_ERROR_NORMAL,      // error control type
                cmd,                       // path to service's binary
                NULL,                      // no load ordering group
                NULL,                      // no tag identifier
                NULL,                      // no dependencies
                NULL,                      // LocalSystem account
                NULL);                     // no password

        if (schService == NULL)
        {
                CloseServiceHandle(schSCManager);
                winerr("Create service");
        }
        else
                printf("Service installed successfully\n");

        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
}

VOID SvcRemove()
{
        SC_HANDLE schSCManager;
        SC_HANDLE schService;

        schSCManager = OpenSCManager(
                NULL,                    // local computer
                NULL,                    // ServicesActive database
                SC_MANAGER_ALL_ACCESS);  // full access rights

        if (NULL == schSCManager)
                winerr("Open service manager");

        schService = OpenService(
                schSCManager,              // SCM database
                SVCNAME,                   // name of service
                DELETE);                   // intention

        if (schService == NULL)
        {
                CloseServiceHandle(schSCManager);
                winerr("Open service");
        }

        if ( DeleteService(schService) == 0 )
        {
                CloseServiceHandle(schSCManager);
                winerr("Delete service");
        }

        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);
        deleteRegistryEntries();

        printf("Service removed successfully\n");
}

VOID SvcStart()
{
        SC_HANDLE schSCManager;
        SC_HANDLE schService;

        schSCManager = OpenSCManager(
                NULL,                    // local computer
                NULL,                    // ServicesActive database
                SC_MANAGER_ALL_ACCESS);  // full access rights

        if (NULL == schSCManager)
                winerr("Open service manager");

        schService = OpenService(
                schSCManager,              // SCM database
                SVCNAME,                   // name of service
                SERVICE_START);            // intention

        if (schService == NULL)
        {
                CloseServiceHandle(schSCManager);
                winerr("Open service");
        }

        if ( StartService(
                     schService,        // Service
                     0,                 // number of args
                     NULL               // args
                     ) == 0 )
        {
                CloseServiceHandle(schService);
                CloseServiceHandle(schSCManager);
                winerr("Start service");
        }

        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);

        printf("Service started successfully\n");
}

VOID SvcStop()
{
        SC_HANDLE schSCManager;
        SC_HANDLE schService;

        schSCManager = OpenSCManager(
                NULL,                    // local computer
                NULL,                    // ServicesActive database
                SC_MANAGER_ALL_ACCESS);  // full access rights

        if (NULL == schSCManager)
                winerr("Open service manager");

        schService = OpenService(
                schSCManager,              // SCM database
                SVCNAME,                   // name of service
                SERVICE_STOP);             // intention

        if (schService == NULL)
        {
                CloseServiceHandle(schSCManager);
                winerr("Open service");
        }

        SERVICE_STATUS st;

        if ( ControlService(
                     schService,                // service
                     SERVICE_CONTROL_STOP,      // action
                     &st                        // result
                     ) == 0 )
        {
                CloseServiceHandle(schService);
                CloseServiceHandle(schSCManager);
                winerr("Stop service");
        }

        CloseServiceHandle(schService);
        CloseServiceHandle(schSCManager);

        printf("Service stopped successfully\n");
}

//
// Purpose:
//   Entry point for the service
//
// Parameters:
//   dwArgc - Number of arguments in the lpszArgv array
//   lpszArgv - Array of strings. The first string is the name of
//     the service and subsequent strings are passed by the process
//     that called the StartService function to start the service.
//
// Return value:
//   None.
//
VOID WINAPI SvcMain( DWORD dwArgc, LPTSTR *lpszArgv )
{
    // Register the handler function for the service

    gSvcStatusHandle = RegisterServiceCtrlHandler(
        SVCNAME,
        SvcCtrlHandler);

    if( !gSvcStatusHandle )
    {
        SvcReportEvent(TEXT("RegisterServiceCtrlHandler"));
        return;
    }

    // These SERVICE_STATUS members remain as set here

    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    gSvcStatus.dwServiceSpecificExitCode = 0;

    // Report initial status to the SCM

    ReportSvcStatus( SERVICE_START_PENDING, NO_ERROR, 3000 );

    // Perform service-specific initialization and work.

    SvcInit( dwArgc, lpszArgv );
}

//
// Purpose:
//   The service code
//
// Parameters:
//   dwArgc - Number of arguments in the lpszArgv array
//   lpszArgv - Array of strings. The first string is the name of
//     the service and subsequent strings are passed by the process
//     that called the StartService function to start the service.
//
// Return value:
//   None
//
VOID SvcInit( DWORD dwArgc, LPTSTR *lpszArgv)
{
    // TO_DO: Declare and set any required variables.
    //   Be sure to periodically call ReportSvcStatus() with
    //   SERVICE_START_PENDING. If initialization fails, call
    //   ReportSvcStatus with SERVICE_STOPPED.

    // Create an event. The control handler function, SvcCtrlHandler,
    // signals this event when it receives the stop control code.

    ghSvcStopEvent = CreateEvent(
                         NULL,    // default security attributes
                         TRUE,    // manual reset event
                         FALSE,   // not signaled
                         NULL);   // no name

    if ( ghSvcStopEvent == NULL)
    {
        ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
        return;
    }

    // Report running status when initialization is complete.

    ReportSvcStatus( SERVICE_RUNNING, NO_ERROR, 0 );

    // TO_DO: Perform work until service stops.

    while(1)
    {
        // Check whether to stop the service.

        WaitForSingleObject(ghSvcStopEvent, INFINITE);

        ReportSvcStatus( SERVICE_STOPPED, NO_ERROR, 0 );
        return;
    }
}

//
// Purpose:
//   Sets the current service status and reports it to the SCM.
//
// Parameters:
//   dwCurrentState - The current state (see SERVICE_STATUS)
//   dwWin32ExitCode - The system error code
//   dwWaitHint - Estimated time for pending operation,
//     in milliseconds
//
// Return value:
//   None
//
VOID ReportSvcStatus( DWORD dwCurrentState,
                      DWORD dwWin32ExitCode,
                      DWORD dwWaitHint)
{
    static DWORD dwCheckPoint = 1;

    // Fill in the SERVICE_STATUS structure.

    gSvcStatus.dwCurrentState = dwCurrentState;
    gSvcStatus.dwWin32ExitCode = dwWin32ExitCode;
    gSvcStatus.dwWaitHint = dwWaitHint;

    if (dwCurrentState == SERVICE_START_PENDING)
        gSvcStatus.dwControlsAccepted = 0;
    else gSvcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;

    if ( (dwCurrentState == SERVICE_RUNNING) ||
           (dwCurrentState == SERVICE_STOPPED) )
        gSvcStatus.dwCheckPoint = 0;
    else gSvcStatus.dwCheckPoint = dwCheckPoint++;

    // Report the status of the service to the SCM.
    SetServiceStatus( gSvcStatusHandle, &gSvcStatus );
}

//
// Purpose:
//   Called by SCM whenever a control code is sent to the service
//   using the ControlService function.
//
// Parameters:
//   dwCtrl - control code
//
// Return value:
//   None
//
VOID WINAPI SvcCtrlHandler( DWORD dwCtrl )
{
   // Handle the requested control code.

   switch(dwCtrl)
   {
      case SERVICE_CONTROL_STOP:
         ReportSvcStatus(SERVICE_STOP_PENDING, NO_ERROR, 0);

         // Signal the service to stop.

         SetEvent(ghSvcStopEvent);
         ReportSvcStatus(gSvcStatus.dwCurrentState, NO_ERROR, 0);

         return;

      case SERVICE_CONTROL_INTERROGATE:
         break;

      default:
         break;
   }

}

VOID SvcReportEvent(LPTSTR szFunction)
{
    HANDLE hEventSource;
    LPCTSTR lpszStrings[2];
    TCHAR Buffer[80];

    hEventSource = RegisterEventSource(NULL, SVCNAME);

    if( NULL != hEventSource )
    {
        StringCchPrintf(Buffer, 80, TEXT("%s failed with %d"), szFunction, GetLastError());

        lpszStrings[0] = SVCNAME;
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
