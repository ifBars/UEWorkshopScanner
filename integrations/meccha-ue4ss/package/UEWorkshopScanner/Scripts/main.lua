local MOD_NAME = "UEWorkshopScanner"
local STEAM_APP_ID = "4704690"
local MOUNT_HOOK_PATH =
    "/Script/PenguinHotel.ModBlueprintLibrary:MountIoStoreAndGetLevelsFromAssetRegistry"
local PREFIX = "[" .. MOD_NAME .. "] "

local function log(message)
    print(PREFIX .. message .. "\n")
end

local function normalize(path)
    return path:gsub("/", "\\"):gsub("\\+$", "")
end

local function dirname(path)
    return normalize(path):match("^(.*)\\[^\\]+$")
end

local function quote(path)
    return '"' .. path:gsub('"', '""') .. '"'
end

local function mod_root()
    local managed_mods = os.getenv("SHIMLOADER_MOD_DIR")
    if managed_mods and managed_mods ~= "" then
        return normalize(managed_mods) .. "\\" .. MOD_NAME
    end

    local source = debug.getinfo(1, "S").source:gsub("^@", "")
    return dirname(dirname(normalize(source)))
end

local function reports_directory()
    local path = mod_root() .. "\\reports"
    os.execute("if not exist " .. quote(path) .. " mkdir " .. quote(path))
    return path
end

local function workshop_root()
    local directories = IterateGameDirectories()
    local win64 = directories
        and directories.Game
        and directories.Game.Binaries
        and directories.Game.Binaries.Win64
    local path = win64 and win64.__absolute_path
    if not path then
        return nil
    end

    local steamapps = normalize(path)
    for _ = 1, 5 do
        steamapps = dirname(steamapps)
        if not steamapps then
            return nil
        end
    end
    return steamapps .. "\\workshop\\content\\" .. STEAM_APP_ID
end

local mount_scan_states = {}

local function fstring_value(argument)
    local ok, value = pcall(function()
        return argument:get():ToString()
    end)
    if not ok or not value or value == "" then
        return nil
    end
    return normalize(value)
end

local function read_scan_exit_code(path)
    local status = io.open(path, "r")
    if not status then
        return nil
    end
    local value = tonumber(status:read("*l"))
    status:close()
    return value
end

local function deny_mount_attempt(mod_folder_argument, folder)
    local blocked_path = folder .. "\\.ue-workshop-scanner-pending"
    local ok, failure = pcall(function()
        mod_folder_argument:set(blocked_path)
    end)
    if not ok then
        log("Could not gate the mount path: " .. tostring(failure))
    end
end

local function close_game_after_block(state, item_id, disposition, report)
    if state.termination_scheduled then
        return
    end
    state.termination_scheduled = true
    local scanner = mod_root() .. "\\bin\\ue-workshop-scanner.exe"
    log(
        "Closing the game and showing a warning because Workshop item "
        .. item_id
        .. " did not pass scanning."
    )
    ExecuteAsync(function()
        local command = table.concat({
            'cmd.exe /d /s /c "taskkill /f /im PenguinHotel-Win64-Shipping.exe > nul 2>&1',
            '& start ""',
            quote(scanner),
            "--notify-block",
            "--item-id",
            item_id,
            "--decision",
            disposition,
            "--report",
            quote(report) .. '"'
        }, " ")
        os.execute(command)
    end)
end

local function gate_mount_candidate(mod_folder_argument)
    local folder = fstring_value(mod_folder_argument)
    local workshop = workshop_root()
    if not folder or not workshop then
        return
    end

    local normalized_workshop = normalize(workshop)
    local expected_prefix = normalized_workshop:lower() .. "\\"
    if folder:lower():sub(1, #expected_prefix) ~= expected_prefix then
        log("Ignoring mount path outside the Workshop root: " .. folder)
        return
    end

    local relative = folder:sub(#expected_prefix + 1)
    local item_id = relative:match("^(%d+)$")
    if not item_id then
        return
    end

    local scanner = mod_root() .. "\\bin\\ue-workshop-scanner.exe"
    local scanner_file = io.open(scanner, "rb")
    if not scanner_file then
        log("Cannot observe mount; scanner binary is missing: " .. scanner)
        return
    end
    scanner_file:close()

    local report = reports_directory() .. "\\mount-" .. item_id .. ".json"
    local process_log = reports_directory() .. "\\mount-" .. item_id .. ".log"
    local status_path = reports_directory() .. "\\mount-" .. item_id .. ".status"
    local state = mount_scan_states[folder]

    if state then
        local exit_code = read_scan_exit_code(status_path)
        if exit_code == 0 then
            if not state.decision_logged then
                state.decision_logged = true
                log("Allowing Workshop item " .. item_id .. " after a clean scan.")
            end
            return
        end

        deny_mount_attempt(mod_folder_argument, folder)
        if exit_code ~= nil and not state.decision_logged then
            state.decision_logged = true
            local disposition = ({
                [2] = "review",
                [3] = "block",
                [4] = "incomplete"
            })[exit_code] or "error"
            log(string.format(
                "Blocking Workshop item %s after scanner exit code %d (%s).",
                item_id,
                exit_code,
                disposition
            ))
            close_game_after_block(state, item_id, disposition, report)
        end
        return
    end

    os.remove(report)
    os.remove(process_log)
    os.remove(status_path)
    mount_scan_states[folder] = {
        item_id = item_id,
        decision_logged = false
    }
    deny_mount_attempt(mod_folder_argument, folder)
    log("Holding pre-mount Workshop item " .. item_id .. " while an asynchronous scan runs.")
    ExecuteAsync(function()
        local scanner_command = table.concat({
            quote(scanner),
            quote(folder),
            "--game",
            "meccha-chameleon",
            "--format",
            "json",
            "--output",
            quote(report)
        }, " ") .. " > " .. quote(process_log) .. " 2>&1"
        local inner_command = table.concat({
            scanner_command,
            '& set "uew_exit=!errorlevel!"',
            "& > " .. quote(status_path) .. " echo !uew_exit!",
            "& exit /b !uew_exit!"
        }, " ")
        local command = 'cmd.exe /d /v:on /s /c "' .. inner_command .. '"'
        log("Executing mount scan command: " .. command)
        local succeeded, reason, exit_code = os.execute(command)
        local code = tonumber(exit_code) or (succeeded and 0 or -1)
        log(string.format(
            "Mount scan process finished for item %s with exit code %d (%s). Report: %s",
            item_id,
            code,
            tostring(reason),
            report
        ))
    end)
end

local mount_hook = nil
local last_hook_error = nil

local function install_mount_gate_hook()
    if mount_hook then
        return true
    end

    local ok, pre_id, post_id = pcall(
        RegisterHook,
        MOUNT_HOOK_PATH,
        function(...)
            gate_mount_candidate(select(2, ...))
        end,
        function() end
    )
    if not ok then
        local failure = tostring(pre_id)
        if failure ~= last_hook_error then
            last_hook_error = failure
            log("Mount gate is not ready yet: " .. failure)
        end
        return false
    end

    mount_hook = {
        pre_id = pre_id,
        post_id = post_id
    }
    last_hook_error = nil
    log("Protection active. Workshop maps will be scanned before mounting.")
    return true
end

if not install_mount_gate_hook() then
    log("Protection will activate automatically when the game finishes loading.")
    local retry_handle
    retry_handle = LoopInGameThreadWithDelay(1000, function()
        if install_mount_gate_hook() then
            CancelDelayedAction(retry_handle)
        end
    end)
end
