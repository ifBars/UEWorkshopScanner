#include <Windows.h>
#include <bcrypt.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace
{
constexpr std::uintptr_t kMountCallRva = 0x5627210;
constexpr std::uintptr_t kMountImplementationRva = 0x562A5E0;
constexpr std::uint64_t kSupportedImageSize = 169234944;
constexpr std::wstring_view kSupportedSha256 =
    L"001B329EDB0F37B6D3157D8334EDBD58A83D092D9748F9439DD1B59F2CACE36A";
constexpr std::array<std::uint8_t, 5> kExpectedCall = {
    0xE8, 0xCB, 0x33, 0x00, 0x00,
};

struct FStringView
{
    const wchar_t* data;
    std::int32_t length;
    std::int32_t capacity;
};

using MountPakFromWorkshopItem = bool (*)(
    void* subsystem,
    const FStringView* workshop_item_id,
    const FStringView* pak_file_name,
    std::int32_t pak_order,
    FStringView* mounted_pak_file_path,
    FStringView* error_message);

HMODULE g_dll_module{};
std::uint8_t* g_mount_call{};
void* g_relay{};
MountPakFromWorkshopItem g_mount{};
std::mutex g_log_mutex;

std::filesystem::path log_path()
{
    std::array<wchar_t, 32768> path{};
    const auto length = GetModuleFileNameW(g_dll_module, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length == path.size())
    {
        return L"UEWorkshopScannerNative.log";
    }

    return std::filesystem::path(std::wstring_view(path.data(), length))
        .parent_path()
        .parent_path() /
        L"native-hook.log";
}

void log(std::wstring_view message)
{
    std::scoped_lock lock(g_log_mutex);
    std::wofstream output(log_path(), std::ios::app);
    if (!output)
    {
        return;
    }

    SYSTEMTIME time{};
    GetLocalTime(&time);
    output << L'[' << std::setfill(L'0') << std::setw(2) << time.wHour << L':'
           << std::setw(2) << time.wMinute << L':' << std::setw(2) << time.wSecond
           << L'.' << std::setw(3) << time.wMilliseconds << L"] " << message << L'\n';
}

std::wstring copy_fstring(const FStringView* value)
{
    if (value == nullptr || value->data == nullptr || value->length <= 0 ||
        value->length > 32768 || value->capacity < value->length)
    {
        return {};
    }

    auto length = static_cast<std::size_t>(value->length);
    if (length > 0 && value->data[length - 1] == L'\0')
    {
        --length;
    }
    return std::wstring(value->data, length);
}

std::wstring sha256(const std::filesystem::path& path)
{
    BCRYPT_ALG_HANDLE algorithm{};
    BCRYPT_HASH_HANDLE hash{};
    DWORD object_size{};
    DWORD bytes_written{};
    std::vector<std::uint8_t> object;
    std::array<std::uint8_t, 32> digest{};

    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0 ||
        BCryptGetProperty(
            algorithm,
            BCRYPT_OBJECT_LENGTH,
            reinterpret_cast<PUCHAR>(&object_size),
            sizeof(object_size),
            &bytes_written,
            0) < 0)
    {
        if (algorithm != nullptr)
        {
            BCryptCloseAlgorithmProvider(algorithm, 0);
        }
        return {};
    }

    object.resize(object_size);
    if (BCryptCreateHash(
            algorithm,
            &hash,
            object.data(),
            static_cast<ULONG>(object.size()),
            nullptr,
            0,
            0) < 0)
    {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    std::ifstream input(path, std::ios::binary);
    std::array<char, 1024 * 1024> buffer{};
    while (input)
    {
        input.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const auto count = input.gcount();
        if (count > 0 &&
            BCryptHashData(
                hash,
                reinterpret_cast<PUCHAR>(buffer.data()),
                static_cast<ULONG>(count),
                0) < 0)
        {
            BCryptDestroyHash(hash);
            BCryptCloseAlgorithmProvider(algorithm, 0);
            return {};
        }
    }

    if (BCryptFinishHash(hash, digest.data(), static_cast<ULONG>(digest.size()), 0) < 0)
    {
        BCryptDestroyHash(hash);
        BCryptCloseAlgorithmProvider(algorithm, 0);
        return {};
    }

    BCryptDestroyHash(hash);
    BCryptCloseAlgorithmProvider(algorithm, 0);

    std::wostringstream result;
    result << std::uppercase << std::hex << std::setfill(L'0');
    for (const auto byte : digest)
    {
        result << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return result.str();
}

void* allocate_relay_near(const std::uint8_t* call_site)
{
    SYSTEM_INFO system_info{};
    GetSystemInfo(&system_info);

    const auto granularity = static_cast<std::uintptr_t>(system_info.dwAllocationGranularity);
    const auto origin = reinterpret_cast<std::uintptr_t>(call_site);
    const auto lower = origin > 0x7FFF0000 ? origin - 0x7FFF0000 : 0;
    const auto upper = origin + 0x7FFF0000;
    auto cursor = lower;

    while (cursor < upper)
    {
        MEMORY_BASIC_INFORMATION region{};
        if (VirtualQuery(reinterpret_cast<void*>(cursor), &region, sizeof(region)) == 0)
        {
            break;
        }

        const auto base = reinterpret_cast<std::uintptr_t>(region.BaseAddress);
        const auto end = base + region.RegionSize;
        if (region.State == MEM_FREE)
        {
            const auto candidate = (base + granularity - 1) & ~(granularity - 1);
            if (candidate + 64 <= end && candidate >= lower && candidate <= upper)
            {
                if (auto* allocation = VirtualAlloc(
                        reinterpret_cast<void*>(candidate),
                        64,
                        MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE))
                {
                    return allocation;
                }
            }
        }

        if (end <= cursor)
        {
            break;
        }
        cursor = end;
    }

    return nullptr;
}

bool mount_hook(
    void* subsystem,
    const FStringView* workshop_item_id,
    const FStringView* pak_file_name,
    std::int32_t pak_order,
    FStringView* mounted_pak_file_path,
    FStringView* error_message)
{
    std::wostringstream message;
    message << L"pre-mount item=\"" << copy_fstring(workshop_item_id) << L"\" pak=\""
            << copy_fstring(pak_file_name) << L"\" order=" << pak_order;
    log(message.str());

    const auto result = g_mount(
        subsystem,
        workshop_item_id,
        pak_file_name,
        pak_order,
        mounted_pak_file_path,
        error_message);
    log(result ? L"mount allowed by observe-only diagnostic"
               : L"game mount implementation returned failure");
    return result;
}

bool install_hook()
{
    const auto game_module = GetModuleHandleW(nullptr);
    if (game_module == nullptr)
    {
        log(L"disabled: main executable module was unavailable");
        return false;
    }

    std::array<wchar_t, 32768> executable_path{};
    const auto path_length =
        GetModuleFileNameW(nullptr, executable_path.data(), static_cast<DWORD>(executable_path.size()));
    if (path_length == 0 || path_length == executable_path.size())
    {
        log(L"disabled: executable path was unavailable");
        return false;
    }

    const std::filesystem::path path(std::wstring_view(executable_path.data(), path_length));
    std::error_code error;
    if (std::filesystem::file_size(path, error) != kSupportedImageSize ||
        sha256(path) != kSupportedSha256)
    {
        log(L"disabled: unsupported Meccha Chameleon executable fingerprint");
        return false;
    }

    auto* image = reinterpret_cast<std::uint8_t*>(game_module);
    g_mount_call = image + kMountCallRva;
    if (!std::equal(kExpectedCall.begin(), kExpectedCall.end(), g_mount_call))
    {
        log(L"disabled: pre-mount call-site bytes did not match");
        g_mount_call = nullptr;
        return false;
    }

    g_mount = reinterpret_cast<MountPakFromWorkshopItem>(image + kMountImplementationRva);
    g_relay = allocate_relay_near(g_mount_call);
    if (g_relay == nullptr)
    {
        log(L"disabled: no executable relay allocation was available within rel32 range");
        return false;
    }

    std::array<std::uint8_t, 12> relay = {
        0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0,
    };
    const auto hook_address = reinterpret_cast<std::uintptr_t>(&mount_hook);
    std::memcpy(relay.data() + 2, &hook_address, sizeof(hook_address));
    std::memcpy(g_relay, relay.data(), relay.size());
    FlushInstructionCache(GetCurrentProcess(), g_relay, relay.size());

    const auto source = reinterpret_cast<std::intptr_t>(g_mount_call + 5);
    const auto destination = reinterpret_cast<std::intptr_t>(g_relay);
    const auto displacement64 = destination - source;
    if (displacement64 < INT32_MIN || displacement64 > INT32_MAX)
    {
        log(L"disabled: allocated relay was outside rel32 range");
        VirtualFree(g_relay, 0, MEM_RELEASE);
        g_relay = nullptr;
        return false;
    }

    std::array<std::uint8_t, 5> patched_call = {0xE8, 0, 0, 0, 0};
    const auto displacement = static_cast<std::int32_t>(displacement64);
    std::memcpy(patched_call.data() + 1, &displacement, sizeof(displacement));

    DWORD old_protection{};
    if (!VirtualProtect(g_mount_call, patched_call.size(), PAGE_EXECUTE_READWRITE, &old_protection))
    {
        log(L"disabled: VirtualProtect failed for the pre-mount call site");
        VirtualFree(g_relay, 0, MEM_RELEASE);
        g_relay = nullptr;
        return false;
    }

    std::memcpy(g_mount_call, patched_call.data(), patched_call.size());
    FlushInstructionCache(GetCurrentProcess(), g_mount_call, patched_call.size());
    DWORD ignored{};
    VirtualProtect(g_mount_call, patched_call.size(), old_protection, &ignored);
    log(L"installed observe-only native pre-mount diagnostic");
    return true;
}

void uninstall_hook()
{
    if (g_mount_call != nullptr)
    {
        DWORD old_protection{};
        if (VirtualProtect(g_mount_call, kExpectedCall.size(), PAGE_EXECUTE_READWRITE, &old_protection))
        {
            std::memcpy(g_mount_call, kExpectedCall.data(), kExpectedCall.size());
            FlushInstructionCache(GetCurrentProcess(), g_mount_call, kExpectedCall.size());
            DWORD ignored{};
            VirtualProtect(g_mount_call, kExpectedCall.size(), old_protection, &ignored);
        }
        g_mount_call = nullptr;
    }

    if (g_relay != nullptr)
    {
        VirtualFree(g_relay, 0, MEM_RELEASE);
        g_relay = nullptr;
    }
    g_mount = nullptr;
}

// UE4SS normally supplies this base class through its private C++ SDK. This ABI-only
// lifecycle shim deliberately uses no UE4SS imports: UE4SS only stores the returned
// pointer and dispatches these virtual slots. It is pinned to UE4SS 3.0.1.
class Ue4ssLifecycleShim
{
  public:
    virtual ~Ue4ssLifecycleShim() = default;
    virtual void on_update() {}
    virtual void on_unreal_init() {}
    virtual void on_ui_init() {}
    virtual void on_program_start() {}
    virtual void deprecated_on_lua_start_named() {}
    virtual void deprecated_on_lua_start() {}
    virtual void deprecated_on_lua_stop_named() {}
    virtual void deprecated_on_lua_stop() {}
    virtual void on_dll_load() {}
    virtual void render_tab() {}
    virtual void on_lua_start_named() {}
    virtual void on_lua_start() {}
    virtual void on_lua_stop_named() {}
    virtual void on_lua_stop() {}
    virtual void on_cpp_mods_loaded() {}
};
} // namespace

extern "C" __declspec(dllexport) Ue4ssLifecycleShim* start_mod()
{
    log(L"starting native diagnostic for UE4SS 3.0.1");
    install_hook();
    return new Ue4ssLifecycleShim();
}

extern "C" __declspec(dllexport) void uninstall_mod(Ue4ssLifecycleShim* mod)
{
    uninstall_hook();
    delete mod;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        g_dll_module = module;
        DisableThreadLibraryCalls(module);
    }
    return TRUE;
}

