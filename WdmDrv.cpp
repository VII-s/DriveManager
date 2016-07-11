#include "stdafx.h"

#include <windows.h>
#include <newdev.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <regstr.h>

#pragma comment(lib, "newdev.lib")
#pragma comment(lib, "setupapi.lib")

#ifndef MAX_DEVICE_ID_LEN
#define MAX_DEVICE_ID_LEN     200
#define MAX_DEVNODE_ID_LEN    MAX_DEVICE_ID_LEN
#define MAX_GUID_STRING_LEN   39          // 38 chars + terminator null
#define MAX_CLASS_NAME_LEN    32
#endif

#ifdef DLL
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT 
#endif

/****************************************************************************/
void StrSubstring(TCHAR *szData, int startIndex, int length)
{
	if (length < 0)
	{
		length = 0;
	}
	if (length >= (short)_tcslen(szData))
	{
		return;
	}

	memmove(szData, szData + startIndex, length * sizeof(TCHAR));
	szData[length] = 0;
}
void StrLTrim(TCHAR *szData)
{
	TCHAR *ptr = szData;

	while (_istspace(*ptr))
	{
		ptr++;
	}

	if (_tcscmp(ptr, szData))
	{
		int wLen = _tcslen(szData) - (ptr - szData);
		memmove(szData, ptr, (wLen + 1) * sizeof(TCHAR));
	}
}
void StrRTrim(TCHAR *szData)
{
	TCHAR *ptr = szData + _tcslen(szData);
	TCHAR *pTmp = ptr;

	while (_istspace(*ptr))
	{
		ptr--;
	}

	if (ptr != szData + _tcslen(szData))
	{
		int wLen = _tcslen(szData) - _tcslen(ptr) + 1;
		memmove(szData, ptr, (wLen + 1) * sizeof(TCHAR));
	}
}
void FindComma(TCHAR *szData)
{
	int wLen = _tcslen(szData);
	int wIdx;
	int wLoop;
	TCHAR  szTmp[MAX_DEVICE_ID_LEN] = { 0 };
	RtlZeroMemory(szTmp, sizeof(TCHAR) * MAX_DEVICE_ID_LEN);

	for (wIdx = 0, wLoop = 0; wLoop < wLen; wLoop++)
	{
		if (szData[wLoop] == ',')
		{
			szData[wLoop] = '.';
		}
		else if (szData[wLoop] == ' ')
		{
			continue;
		}
		szTmp[wIdx++] = szData[wLoop];
	}
	memcpy(szData, szTmp, wIdx*sizeof(TCHAR));
	szData[wIdx] = 0;
}
BOOLEAN FindSectionName(FILE *pFile, const TCHAR* szKey)
{
	TCHAR szData[MAX_DEVICE_ID_LEN] = { 0 };
	RtlZeroMemory(szData, sizeof(TCHAR) * MAX_DEVICE_ID_LEN);

	if (!pFile)
	{
		return false;
	}

	rewind(pFile);
	while (!feof(pFile))
	{
		_fgetts(szData, 255, pFile);
		szData[_tcslen(szData) - 1] = 0;
		if (!_tcsncmp(szKey, szData, _tcslen(szKey)))
			return true;
	}
	return false;
}
/*******************************************************************************/
BOOLEAN GetManufacturer(FILE *pFile, TCHAR *szManu)
{
	TCHAR szData[MAX_DEVICE_ID_LEN] = { 0 };
	RtlZeroMemory(szData, sizeof(TCHAR) * MAX_DEVICE_ID_LEN);

	if (!FindSectionName(pFile, _T("[Manufacturer]")))
	{
		return false;
	}

	RtlZeroMemory(szData, sizeof(TCHAR) * MAX_DEVICE_ID_LEN);

	while (!feof(pFile))
	{
		TCHAR *str = 0L;

		_fgetts(szData, 127, pFile);
		szData[_tcslen(szData) - 1] = 0;
		StrLTrim(szData);
		StrRTrim(szData);
		if (!*szData)
		{
			continue;
		}
		if (szData[0] == ';')
		{
			continue;
		}

		if (_tcschr(szData, '['))
		{
			StrLTrim(szData);
			if (szData[0] != ';')
			{
				return false;
			}
			else
			{
				continue;
			}
		}

		str = _tcschr(szData, '=');

		if (*str)
		{
			TCHAR  szTmp[128] = { 0 };
			int pos = str - szData + 1;
			StrSubstring(szData, pos, _tcslen(szData) - pos);
			StrLTrim(szData);
			StrRTrim(szData);
			FindComma(szData);

			memmove(szManu, szData, _tcslen(szData));
			return true;
		}
	}
	return false;
}
BOOLEAN DLLEXPORT GetHardWareID(FILE *pFile, TCHAR* szHardWareID)
{
	TCHAR szManu[MAX_DEVICE_ID_LEN];
	TCHAR szData[MAX_DEVICE_ID_LEN];
	RtlZeroMemory(szManu, sizeof(TCHAR) * MAX_DEVICE_ID_LEN);
	RtlZeroMemory(szData, sizeof(TCHAR) * MAX_DEVICE_ID_LEN);
	GetManufacturer(pFile, szManu);

	szData[0] = '[';
	_tcscat(szData, szManu);
	_tcscat(szData, _T("]"));

	if (!FindSectionName(pFile, szData))
	{
		return false;
	}
	RtlZeroMemory(szData, sizeof(char) * 128);

	while (!feof(pFile))
	{
		TCHAR *str = 0L;

		_fgetts(szData, 127, pFile);
		szData[_tcslen(szData) - 1] = 0;
		StrLTrim(szData);
		StrRTrim(szData);
		if (!*szData)
		{
			continue;
		}
		if (szData[0] == ';')
		{
			continue;
		}

		if (_tcschr(szData, '['))
		{
			StrLTrim(szData);
			if (szData[0] != ';')
			{
				return false;
			}
			else
			{
				continue;
			}
		}

		str = _tcschr(szData, ',');

		if (*str)
		{
			TCHAR  szTmp[128] = { 0 };
			int pos = str - szData + 1;
			StrSubstring(szData, pos, _tcslen(szData) - pos);
			StrLTrim(szData);
			StrRTrim(szData);
			memmove(szHardWareID, szData, _tcslen(szData));
			return true;
		}
	}
	return false;
}
BOOLEAN DLLEXPORT IsDisabled(HDEVINFO hDevInfo, DWORD dwDevID)
{
	SP_DEVINFO_DATA DevInfoData = { sizeof(SP_DEVINFO_DATA) };
	DWORD    dwDevStatus, dwProblem;
	if (!SetupDiEnumDeviceInfo(hDevInfo, dwDevID, &DevInfoData))
	{
		//OutputDebugString("SetupDiEnumDeviceInfo FAILED");
		return FALSE;
	}

	if (CM_Get_DevNode_Status(&dwDevStatus, &dwProblem, DevInfoData.DevInst, 0) != CR_SUCCESS)
	{
		return FALSE;
	}

	return (dwDevStatus & DN_HAS_PROBLEM) != 0 && dwProblem == CM_PROB_DISABLED;
}
BOOLEAN DLLEXPORT IsEnabled(HDEVINFO hDevInfo, DWORD dwDevID)
{
	SP_DEVINFO_DATA DevInfoData = { sizeof(SP_DEVINFO_DATA) };
	DWORD    dwDevStatus, dwProblem;
	if (!SetupDiEnumDeviceInfo(hDevInfo, dwDevID, &DevInfoData))
	{
		//OutputDebugString("SetupDiEnumDeviceInfo FAILED");
		return FALSE;
	}

	if (CM_Get_DevNode_Status(&dwDevStatus, &dwProblem, DevInfoData.DevInst, 0) != CR_SUCCESS)
	{
		return FALSE;
	}

	return (dwDevStatus & (DN_HAS_PROBLEM | DN_NEED_RESTART)) == 0;
}
BOOLEAN StateChange(HDEVINFO hDevInfo, DWORD dwDevID, DWORD dwNewState)
{
	SP_PROPCHANGE_PARAMS PropChangeParams;
	SP_DEVINFO_DATA      DevInfoData = { sizeof(SP_DEVINFO_DATA) };

	//查询设备信息
	if (!SetupDiEnumDeviceInfo(hDevInfo, dwDevID, &DevInfoData))
	{
		//OutputDebugString("SetupDiEnumDeviceInfo FAILED");
		return FALSE;
	}

	//设置设备属性变化参数
	PropChangeParams.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
	PropChangeParams.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
	PropChangeParams.Scope = DICS_FLAG_CONFIGSPECIFIC; //使修改的属性保存在所有的硬件属性文件
	PropChangeParams.StateChange = dwNewState;
	PropChangeParams.HwProfile = 0;

	if (!SetupDiSetClassInstallParams(hDevInfo, &DevInfoData, (SP_CLASSINSTALL_HEADER *)&PropChangeParams, sizeof(PropChangeParams)))
	{
		//ShowLastError(MB_OK | MB_ICONSTOP, "SetupDiSetClassInstallParams()");
		return FALSE;
	}

	if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, hDevInfo, &DevInfoData))
	{
		//ShowLastError(MB_OK | MB_ICONSTOP, "SetupDiCallClassInstaller(DIF_PROPERTYCHANGE)");
		return FALSE;
	}

	return TRUE;
}
BOOLEAN DLLEXPORT EnableDevice(HDEVINFO hDevInfo, DWORD dwDevID)
{
	return StateChange(hDevInfo, dwDevID, DICS_ENABLE);
}
BOOLEAN DLLEXPORT DisableDevice(HDEVINFO hDevInfo, DWORD dwDevID)
{
	return StateChange(hDevInfo, dwDevID, DICS_DISABLE);
}
BOOLEAN DLLEXPORT IsInstalled(TCHAR* szHardWareID)
{
	HDEVINFO        hDevInfo = 0L;
	SP_DEVINFO_DATA spDevInfoData = { 0L };
	int             wIdx;
	BOOLEAN         bIsFound;

	hDevInfo = SetupDiGetClassDevs(0L, 0, 0, DIGCF_ALLCLASSES | DIGCF_PRESENT);
	if (hDevInfo == INVALID_HANDLE_VALUE)
	{
		//ShowErrorMsg(GetLastError(), _T("SetupDiGetClassDevs"));
		printf("%d\n%s", GetLastError(), "SetupDiGetClassDevs");
		return false;
	}

	spDevInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
	wIdx = 0;
	bIsFound = false;
	while (++wIdx)
	{
		if (SetupDiEnumDeviceInfo(hDevInfo, wIdx, &spDevInfoData))
		{
			TCHAR *ptr;
			TCHAR *pBuffer = 0L;
			DWORD dwData = 0L;
			DWORD dwRetVal;
			DWORD dwBufSize = 0L;

			while (1)
			{
				dwRetVal = SetupDiGetDeviceRegistryProperty(hDevInfo, &spDevInfoData, SPDRP_HARDWAREID,
					&dwData, (PBYTE)pBuffer, dwBufSize, &dwBufSize);
				if (!dwRetVal)
				{
					dwRetVal = GetLastError();
				}
				else
				{
					break;
				}
				if (dwRetVal == ERROR_INVALID_DATA)
				{
					break;
				}
				else if (dwRetVal == ERROR_INSUFFICIENT_BUFFER)
				{
					if (pBuffer)
					{
						LocalFree(pBuffer);
					}
					pBuffer = (TCHAR *)LocalAlloc(LPTR, dwBufSize);
				}
				else
				{
					printf("%d\n%s", dwRetVal, _T("SetupDiGetDeviceRegistryProperty"));
					SetupDiDestroyDeviceInfoList(hDevInfo);
					return false;
				}
			}

			if (dwRetVal == ERROR_INVALID_DATA)
			{
				continue;
			}

			for (ptr = pBuffer; *ptr && (ptr < &pBuffer[dwBufSize]); ptr += lstrlen(ptr) + sizeof(TCHAR))
			{
				if (!_tcscmp(szHardWareID, ptr))
				{
					bIsFound = true;
					break;
				}
			}
			if (pBuffer)
			{
				LocalFree(pBuffer);
			}
			if (bIsFound)
			{
				break;
			}
		}
		else
			break;
	}
	SetupDiDestroyDeviceInfoList(hDevInfo);
	return bIsFound;
}
DWORD DLLEXPORT FindDevIDByDevDesc(const TCHAR* szHardWareID, const TCHAR *szDeviceDesc)
{
	SP_DEVINFO_DATA spDevInfoData = { 0 };
	HDEVINFO        hDevInfo = 0L;
	int             nIdx, nCount;

	hDevInfo = SetupDiGetClassDevs(0L, 0L, 0, DIGCF_ALLCLASSES | DIGCF_PRESENT);
	if (hDevInfo == INVALID_HANDLE_VALUE)
	{
		printf("%d\n%s", GetLastError(), _T("SetupDiGetClassDevs"));
		return -1;
	}

	nIdx = 0;
	nCount = 0;
	while (1)
	{
		spDevInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
		if (SetupDiEnumDeviceInfo(hDevInfo, nIdx, &spDevInfoData))
		{
			TCHAR szBuf[2048] = { 0 };

			if (SetupDiGetDeviceRegistryProperty(hDevInfo, &spDevInfoData, SPDRP_HARDWAREID,
				0L, (PBYTE)szBuf, 2048, 0L))
			{
				if (_tcsicmp(szHardWareID, szBuf))
				{
					nIdx++;
					continue;
				}
				if (szDeviceDesc != NULL)
				{
					if (SetupDiGetDeviceRegistryProperty(hDevInfo, &spDevInfoData, SPDRP_DEVICEDESC,
						0L, (PBYTE)szBuf, 2048, 0L))
					{
						if (_tcsicmp(szDeviceDesc, szBuf))
						{
							nIdx++;
							continue;
						}
					}
				}
				return nIdx;
			}
		}
		else
		{
			break;
		}
		nIdx++;
	}
	SetupDiDestroyDeviceInfoList(hDevInfo);
	return true;
}
BOOLEAN InstallClassDriver(const TCHAR *szInfName, const TCHAR* szHardWareID)
{
	GUID            guid = { 0 };
	SP_DEVINFO_DATA spDevData = { 0 };
	HDEVINFO        hDevInfo = 0L;
	TCHAR           className[MAX_CLASS_NAME_LEN] = { 0 };
	BOOL            bRebootRequired;

	if (!SetupDiGetINFClass(szInfName, &guid, className, MAX_CLASS_NAME_LEN, 0))
	{
		printf("%d\n%s", GetLastError(), _T("SetupDiGetINFClass"));
		return false;
	}

	hDevInfo = SetupDiCreateDeviceInfoList(&guid, 0);
	if (hDevInfo == INVALID_HANDLE_VALUE)
	{
		printf("%d\n%s", GetLastError(), _T("SetupDiCreateDeviceInfoList"));
		return false;
	}

	spDevData.cbSize = sizeof(SP_DEVINFO_DATA);
	if (!SetupDiCreateDeviceInfo(hDevInfo, className, &guid, 0L, 0L, DICD_GENERATE_ID, &spDevData))
	{
		printf("%d\n%s", GetLastError(), _T("SetupDiCreateDeviceInfo"));
		SetupDiDestroyDeviceInfoList(hDevInfo);
		return false;
	}

	if (!SetupDiSetDeviceRegistryProperty(hDevInfo, &spDevData, SPDRP_HARDWAREID, (PBYTE)szHardWareID,
		(DWORD)(_tcslen(szHardWareID) * 2 * sizeof(TCHAR))))
	{
		printf("%d\n%s", GetLastError(), _T("SetupDiSetDeviceRegistryProperty"));
		SetupDiDestroyDeviceInfoList(hDevInfo);
		return false;
	}

	if (!SetupDiCallClassInstaller(DIF_REGISTERDEVICE, hDevInfo, &spDevData))
	{
		printf("%d\n%s", GetLastError(), _T("SetupDiCallClassInstaller"));
		SetupDiDestroyDeviceInfoList(hDevInfo);
		return false;
	}

	bRebootRequired = 0;
	//if (!UpdateDriverForPlugAndPlayDevices(0L, szHardWareID, szInfName,
	//	INSTALLFLAG_FORCE, &bRebootRequired))
	//{
	//	DWORD dwErrorCode = GetLastError();
	//	//
	//	if (!SetupDiCallClassInstaller(DIF_REMOVE, hDevInfo, &spDevData))
	//	{
	//		printf("%d\n%s", GetLastError(), _T("SetupDiCallClassInstaller(Remove)"));
	//	}
	//	printf("%d\n%s", dwErrorCode, _T("UpdateDriverForPlugAndPlayDevices"));
	//	SetupDiDestroyDeviceInfoList(hDevInfo);
	//	return false;
	//}

	SetupDiDestroyDeviceInfoList(hDevInfo);
	//printf("%d\n%s", 0, _T("Install Successed!"));
	return true;
}
BOOLEAN DLLEXPORT InstallDrv(const TCHAR* szInfName)
{
	HDEVINFO             hDevInfo = 0L;
	GUID                 guid = { 0L };
	TCHAR                szClass[MAX_CLASS_NAME_LEN] = { 0L };
	SP_DEVINSTALL_PARAMS spDevInst = { 0L };
	TCHAR                szHardWareID[MAX_DEVICE_ID_LEN];
	RtlZeroMemory(szHardWareID, sizeof(TCHAR) * MAX_DEVICE_ID_LEN);

	FILE *pInf = _tfopen(szInfName, _T("r"));
	if (!pInf)
	{
		_tprintf(_T("can not open file %s\n"), szInfName);
		return 0;
	}
	GetHardWareID(pInf, szHardWareID);

	if (!SetupDiGetINFClass(szInfName, &guid, szClass, MAX_CLASS_NAME_LEN, 0))
	{
		printf("%d\n%s", GetLastError(), _T("SetupDiGetINFClass"));
		return false;
	}

	hDevInfo = SetupDiGetClassDevs(&guid, 0L, 0L, DIGCF_PRESENT | DIGCF_ALLCLASSES | DIGCF_PROFILE);
	if (!hDevInfo)
	{
		printf("%d\n%s", GetLastError(), _T("SetupDiGetClassDevs"));
		return false;
	}

	spDevInst.cbSize = sizeof(SP_DEVINSTALL_PARAMS);
	if (!SetupDiGetDeviceInstallParams(hDevInfo, 0L, &spDevInst))
	{
		printf("%d\n%s", GetLastError(), _T("SetupDiGetDeviceInstallParams"));
		return false;
	}

	spDevInst.Flags = DI_ENUMSINGLEINF;
	spDevInst.FlagsEx = DI_FLAGSEX_ALLOWEXCLUDEDDRVS;
	_tcscpy(spDevInst.DriverPath, szInfName);
	if (!SetupDiSetDeviceInstallParams(hDevInfo, 0, &spDevInst))
	{
		printf("%d\n%s", GetLastError(), _T("SetupDiSetDeviceInstallParams"));
		return false;
	}

	if (!SetupDiBuildDriverInfoList(hDevInfo, 0, SPDIT_CLASSDRIVER))
	{
		printf("%d\n%s", GetLastError(), _T("SetupDiDeviceInstallParams"));
		return false;
	}

	SetupDiDestroyDeviceInfoList(hDevInfo);
	return InstallClassDriver(szInfName, szHardWareID);
}
BOOLEAN DLLEXPORT InstallOEMDrv(const TCHAR* szInfName)
{
	TCHAR  szHardWareID[MAX_DEVICE_ID_LEN];
	BOOL   bRebootRequired = false;
	FILE   *pInf = _tfopen(szInfName, _T("r"));

	RtlZeroMemory(szHardWareID, sizeof(TCHAR) * MAX_DEVICE_ID_LEN);

	if (!pInf)
	{
		_tprintf(_T("can not open file %s\n"), szInfName);
		return 0;
	}
	GetHardWareID(pInf, szHardWareID);

	if (!SetupCopyOEMInf(szInfName, NULL, SPOST_PATH, SP_COPY_NOOVERWRITE, NULL, 0, NULL, NULL)) 
	{
		if (GetLastError() != ERROR_FILE_EXISTS)
		{
			_tprintf(_T("CopyInf(g_szInfPath) Error %d\n"), GetLastError());
			return FALSE;
		}
	}
	if (UpdateDriverForPlugAndPlayDevices(0, szHardWareID, szInfName, 0, &bRebootRequired))
	{
		return TRUE;
	}
	else
	{
		_tprintf(_T("UpdateDriverForPlugAndPlayDevices Error %d\n"), GetLastError());
	}
	return true;
}
BOOLEAN DLLEXPORT UninstallDrv(const TCHAR* szHardWareID, const TCHAR *szDeviceDesc)
{
	SP_DEVINFO_DATA spDevInfoData = { 0 };
	HDEVINFO        hDevInfo = 0L;
	int             nIdx, nCount;

	hDevInfo = SetupDiGetClassDevs(0L, 0L, 0, DIGCF_ALLCLASSES | DIGCF_PRESENT);
	if (hDevInfo == INVALID_HANDLE_VALUE)
	{
		printf("%d\n%s", GetLastError(), _T("SetupDiGetClassDevs"));
		return false;
	}

	nIdx = 0;
	nCount = 0;
	while (1)
	{
		spDevInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
		if (SetupDiEnumDeviceInfo(hDevInfo, nIdx, &spDevInfoData))
		{
			TCHAR szBuf[2048] = { 0 };

			if (SetupDiGetDeviceRegistryProperty(hDevInfo, &spDevInfoData, SPDRP_HARDWAREID,
				0L, (PBYTE)szBuf, 2048, 0L))
			{
				if (_tcsicmp(szHardWareID, szBuf))
				{
					nIdx++;
					continue;
				}
				if (szDeviceDesc != NULL)
				{
					if (SetupDiGetDeviceRegistryProperty(hDevInfo, &spDevInfoData, SPDRP_DEVICEDESC,
						0L, (PBYTE)szBuf, 2048, 0L))
					{
						if (_tcsicmp(szDeviceDesc, szBuf))
						{
							nIdx++;
							continue;
						}
					}
				}
				if (!SetupDiCallClassInstaller(DIF_REMOVE, hDevInfo, &spDevInfoData))
				{
					printf("%d\n%s", GetLastError(), _T("SetupDiCallClassInstaller(Remove)"));
				}
				return true;
			}
		}
		else
		{
			break;
		}
		nIdx++;
	}
	SetupDiDestroyDeviceInfoList(hDevInfo);
	return true;
}
BOOLEAN DLLEXPORT UninstallAll(const TCHAR* szHardWareID)
{
	SP_DEVINFO_DATA spDevInfoData = { 0 };
	HDEVINFO        hDevInfo = 0L;
	int             nIdx, nCount;
	//
	hDevInfo = SetupDiGetClassDevs(0L, 0L, 0, DIGCF_ALLCLASSES | DIGCF_PRESENT);
	if (hDevInfo == INVALID_HANDLE_VALUE)
	{
		printf("%d\n%s", GetLastError(), _T("SetupDiGetClassDevs"));
		return false;
	}
	
	nIdx = 0;
	nCount = 0;
	while (1)
	{
		spDevInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
		if (SetupDiEnumDeviceInfo(hDevInfo, nIdx, &spDevInfoData))
		{
			TCHAR szBuf[2048] = { 0 };

			if (SetupDiGetDeviceRegistryProperty(hDevInfo, &spDevInfoData, SPDRP_HARDWAREID,
				0L, (PBYTE)szBuf, 2048, 0L))
			{				
				if (!_tcsnicmp(szHardWareID, szBuf, _tcslen(szHardWareID)))
				{
					if (!SetupDiCallClassInstaller(DIF_REMOVE, hDevInfo, &spDevInfoData))
					{
						printf("%d\n%s", GetLastError(), _T("SetupDiCallClassInstaller(Remove)"));
					}
					nCount++;
				}
			}
		}
		else
		{
			break;
		}
		nIdx++;
	}

	//if (nCount != 0)
	//	_tprintf(_T("UnInstall Successed\n"));

	SetupDiDestroyDeviceInfoList(hDevInfo);
	return true;
}
BOOLEAN DLLEXPORT UpdateDrv(const TCHAR *szInfName)
{
	TCHAR   szHardWareID[MAX_DEVICE_ID_LEN];
	BOOL    bRebootRequired = 0;

	RtlZeroMemory(szHardWareID, sizeof(TCHAR) * MAX_DEVICE_ID_LEN);

	FILE    *pInf = _tfopen(szInfName, _T("r"));
	if (!pInf)
	{
		_tprintf(_T("can not open file %s\n"), szInfName);
		return 0;
	}
	GetHardWareID(pInf, szHardWareID);

	if (!UpdateDriverForPlugAndPlayDevices(0L, szHardWareID, szInfName,
		INSTALLFLAG_FORCE, &bRebootRequired))
	{
		DWORD dwErrorCode = GetLastError();
		printf("%d\n%s", dwErrorCode, _T("UpdateDriverForPlugAndPlayDevices"));
		return false;
	}
	return true;
}
BOOLEAN DLLEXPORT RestartDrv(const TCHAR *szInfName, DWORD dwDevID)
{
	return true;
}


#ifdef DLL
BOOL WINAPI DllMain(HANDLE hInst, ULONG ul_reason_for_call, LPVOID lpReserved)
{
	g_hInstance=(HINSTANCE)hInst;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_DETACH:
		break;
	default:
		break;
	}
	return TRUE;
}
#else
int _tmain2(int argc, _TCHAR* argv[])
{
	BOOL bRebootRequired = 0;
	TCHAR szInfPath[MAX_PATH];

	if (argc < 3)
	{
		_tprintf(_T("Please input options!\n"));
		_tprintf(_T("[Options]\n"));
		_tprintf(_T("-i InfFile: Install driver\n"));
		_tprintf(_T("-u InfFile: Uninstall driver\n"));
		return 0;
	}

	_tcscpy(szInfPath, argv[2]);

	TCHAR  szHardWareID[MAX_DEVICE_ID_LEN] = { 0 };
	RtlZeroMemory(szHardWareID, sizeof(TCHAR) * MAX_DEVICE_ID_LEN);

	FILE *pInf = _tfopen(szInfPath, _T("r"));
	if (!pInf)
	{
		_tprintf(_T("can not open file %s\n"), szInfPath);
		return 0;
	}
	GetHardWareID(pInf, szHardWareID);
	fclose(pInf);

	// 安装WDM驱动
	if (_tcscmp(argv[1], TEXT("-i")) == 0)
	{
		if (InstallDrv(szInfPath) == FALSE)
		{
			_tprintf(_T("Start Install WMD Driver failed\n"));
			printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n");
			return 0;
		}
	}
	// 卸载WDM驱动
	else if (_tcscmp(argv[1], TEXT("-ua")) == 0)
	{
		UninstallAll(szHardWareID);
	}
	// 卸载WDM驱动
	else if (_tcscmp(argv[1], TEXT("-u")) == 0)
	{
		UninstallDrv(szHardWareID, argv[3]);
	}

	else if (_tcscmp(argv[1], TEXT("-d")) == 0)
	{
		SP_DEVINFO_DATA spDevInfoData = { 0 };
		HDEVINFO        hDevInfo = 0L;

		hDevInfo = SetupDiGetClassDevs(0L, 0L, 0, DIGCF_ALLCLASSES | DIGCF_PRESENT);
		if (hDevInfo == INVALID_HANDLE_VALUE)
		{
			printf("%d\n%s", GetLastError(), _T("SetupDiGetClassDevs"));
			return false;
		}

		DWORD devid = FindDevIDByDevDesc(szHardWareID, NULL);

		DisableDevice(hDevInfo, devid);
		SetupDiDestroyDeviceInfoList(hDevInfo);
	}
	else if (_tcscmp(argv[1], TEXT("-e")) == 0)
	{
		SP_DEVINFO_DATA spDevInfoData = { 0 };
		HDEVINFO        hDevInfo = 0L;

		hDevInfo = SetupDiGetClassDevs(0L, 0L, 0, DIGCF_ALLCLASSES | DIGCF_PRESENT);
		if (hDevInfo == INVALID_HANDLE_VALUE)
		{
			printf("%d\n%s", GetLastError(), _T("SetupDiGetClassDevs"));
			return false;
		}

		DWORD devid = FindDevIDByDevDesc(szHardWareID, NULL);

		EnableDevice(hDevInfo, devid);
		SetupDiDestroyDeviceInfoList(hDevInfo);
	}
	else if (_tcscmp(argv[1], TEXT("-g")) == 0)
	{
		UpdateDrv(szInfPath);
	}
	else
	{
		_tprintf(_T("Please input options!\n"));
		_tprintf(_T("[Options]\n"));
		_tprintf(_T("-i InfFile: Install driver\n"));
		_tprintf(_T("-u InfFile: Uninstall driver\n"));
		return 0;
	}
	return 1;
}

int _tmain(int argc, _TCHAR* argv[])
{
	BOOL bRebootRequired = 0;
	TCHAR* szPciInfPath = _T("./XHB1509A.inf");
	TCHAR* szComInfPath = _T("./XHB1509A_VSP.inf");

	TCHAR  szPciHID[MAX_DEVICE_ID_LEN] = { 0 };
	RtlZeroMemory(szPciHID, sizeof(TCHAR) * MAX_DEVICE_ID_LEN);
	TCHAR  szComHID[MAX_DEVICE_ID_LEN] = { 0 };
	RtlZeroMemory(szComHID, sizeof(TCHAR) * MAX_DEVICE_ID_LEN);

	// 安装WDM驱动
	if (_tcscmp(argv[1], TEXT("-i")) == 0)
	{
		InstallOEMDrv(szPciInfPath);
		for (int i = 0; i < 16; i++)
		{
			if (InstallDrv(szComInfPath) == FALSE)
			{
				_tprintf(_T("Start Install WMD Driver failed\n"));
				return 0;
			}
		}
		UpdateDrv(szComInfPath);
	}
	// 卸载WDM驱动
	else if (_tcscmp(argv[1], TEXT("-u")) == 0)
	{
		FILE *pPciInf = _tfopen(szPciInfPath, _T("r"));
		if (!pPciInf)
		{
			_tprintf(_T("can not open file %s\n"), szPciInfPath);
			return 0;
		}
		GetHardWareID(pPciInf, szPciHID);
		fclose(pPciInf);

		if (!UninstallAll(szPciHID))
		{
			_tprintf(_T("UninstallAll(szPciHID)\n"));
		}

		FILE *pComInf = _tfopen(szComInfPath, _T("r"));
		if (!pComInf)
		{
			_tprintf(_T("can not open file %s\n"), szComInfPath);
			return 0;
		}
		GetHardWareID(pComInf, szComHID);
		fclose(pComInf);
		if (!UninstallAll(szComHID))
		{
			_tprintf(_T("UninstallAll(szComHID)\n"));
		}
	}	
	else
	{
		_tprintf(_T("Please input options!\n"));
		_tprintf(_T("[Options]\n"));
		_tprintf(_T("-i: Install driver\n"));
		_tprintf(_T("-u: Uninstall driver\n"));
		return 0;
	}
	return 1;
}

#endif

