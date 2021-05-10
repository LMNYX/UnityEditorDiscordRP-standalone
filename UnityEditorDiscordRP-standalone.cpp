#include <iostream>
#include <thread>
#include <csignal>
#include "discord/discord.h"
#include "utils.cpp"

discord::Core* core{};

discord::Activity activity{};

bool IsProcessRunning(const wchar_t* processName)
{
    bool exists = false;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry))
        while (Process32Next(snapshot, &entry))
            if (!_wcsicmp(entry.szExeFile, processName))
                exists = true;

    CloseHandle(snapshot);
    return exists;
}

DWORD FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}

std::string ProcessIdToName(DWORD processId)
{
    std::string ret;
    HANDLE handle = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        processId /* This is the PID, you can find one from windows task manager */
    );
    if (handle)
    {
        DWORD buffSize = 1024;
        CHAR buffer[1024];
        if (QueryFullProcessImageNameA(handle, 0, buffer, &buffSize))
        {
            ret = buffer;
        }
        else
        {
            printf("Error GetModuleBaseNameA : %lu", GetLastError());
        }
        CloseHandle(handle);
    }
    else
    {
        printf("Error OpenProcess : %lu", GetLastError());
    }
    return ret;
}

struct DiscordState {
    discord::User currentUser;

    std::unique_ptr<discord::Core> core;
};

namespace {
    volatile bool interrupted{ false };
}

std::string GetAllWindowsFromProcessID(DWORD dwProcessID, std::vector <HWND>& vhWnds)
{
    try
    {
        // find all hWnds (vhWnds) associated with a process id (dwProcessID)
        HWND hCurWnd = NULL;
        do
        {
            hCurWnd = FindWindowEx(NULL, hCurWnd, NULL, NULL);
            DWORD dwProcID = 0;
            GetWindowThreadProcessId(hCurWnd, &dwProcID);
            if (dwProcID == dwProcessID)
            {
                vhWnds.push_back(hCurWnd);  // add the found hCurWnd to the vector
                char wnd_title[256];
                GetWindowTextA(hCurWnd, wnd_title, sizeof(wnd_title));
                std::string title{ wnd_title };
                if (title == "Default IME" || title == "" || title == "MSCTFIME UI" || title == "Importing" || title == "Unity Package Manager" || title == "Unity")
                    continue;
                return title;
            }
        } while (hCurWnd != NULL);

        return "";
    }
    catch (const std::exception&)
    {
        return "";
    }
}

void UnityUpdater()
{
    try
    {
        std::cout << "Unity listener started! Searching for Unity processes...\n";
        do
        {
            auto doesUnityExist = IsProcessRunning(L"Unity.exe");
            if (doesUnityExist)
            {
                try
                {
                    auto UnityPID = FindProcessId(L"Unity.exe");
                    std::vector <HWND> vh;
                    std::string UnityTitle = GetAllWindowsFromProcessID(UnityPID, vh);
                    if (UnityTitle == "")
                        continue;
                    std::string delimiter = " - ";
                    std::string projectName = UnityTitle.substr(0, UnityTitle.find(delimiter));
                    UnityTitle.erase(0, UnityTitle.find(delimiter) + delimiter.length());
                    std::string sceneName = UnityTitle.substr(0, UnityTitle.find(delimiter));
                    UnityTitle.erase(0, UnityTitle.find(delimiter) + delimiter.length());
                    UnityTitle.erase(0, UnityTitle.find(delimiter) + delimiter.length());
                    std::string unityInfo = UnityTitle.substr(0, UnityTitle.find(delimiter));
                    //std::cout << "Project Name: " << projectName << "\n";
                    //std::cout << "Scene Name:   " << sceneName << "\n";
                    //std::cout << "Unity Name:   " << unityInfo << "\n";

                    std::string detailsRaw = "In project " + projectName;
                    std::string stateRaw = "on scene " + sceneName;

                    const char* state = stateRaw.c_str();
                    const char* details = detailsRaw.c_str();

                    std::this_thread::sleep_for(std::chrono::milliseconds(16));

                    activity.SetState(state);
                    activity.SetDetails(details);
                    activity.GetAssets().SetLargeImage("unity-black");
                    activity.GetAssets().SetLargeText(unityInfo.c_str());

                    core->ActivityManager().UpdateActivity(activity, {});
                }
                catch (std::exception&) { continue; }
            }
            else
                core->ActivityManager().ClearActivity({});
        } while (true);
    }
    catch (std::exception&) { UnityUpdater(); }
}



void DiscordUpdater()
{
    DiscordState state{};
    auto result = discord::Core::Create(838427392871366667, DiscordCreateFlags_NoRequireDiscord, &core);
    
    state.core.reset(core);

    if (!state.core)
    {
        std::cout << "Failed to instantiate discord's core! (" << static_cast<int>(result) << ")\n";
        std::exit(-1);
    }

    std::signal(SIGINT, [](int) { interrupted = true; });

    std::cout << "Discord SDK listener created!\n";
    do
    {
        state.core->RunCallbacks();
        std::this_thread::sleep_for(std::chrono::milliseconds(16));
    } while (!interrupted);
}

int main()
{
    std::cout << "Starting threads...\n";

    std::thread UnityInformationUpdate(UnityUpdater);
    std::thread discord_activity(DiscordUpdater);
    UnityInformationUpdate.join();
    discord_activity.join();
    

    return 0;
}