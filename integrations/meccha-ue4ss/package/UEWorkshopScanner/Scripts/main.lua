local MOD_NAME = "UEWorkshopScanner"
local STEAM_APP_ID = "4704690"
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

local function scan_workshop()
    local root = mod_root()
    local scanner = root .. "\\bin\\ue-workshop-scanner.exe"
    local workshop = workshop_root()
    local report = reports_directory() .. "\\latest.json"

    if not workshop then
        log("Could not derive the Steam Workshop directory from the game path.")
        return
    end

    local scanner_file = io.open(scanner, "rb")
    if not scanner_file then
        log("Scanner binary is missing: " .. scanner)
        return
    end
    scanner_file:close()

    log("Starting an observe-only scan of " .. workshop)
    log("The game is not paused and map loading is not blocked by this prototype.")

    ExecuteAsync(function()
        local command = table.concat({
            quote(scanner),
            quote(workshop),
            "--game meccha-chameleon",
            "--output " .. quote(report)
        }, " ")
        local ok, reason, code = os.execute(command)
        local exit_code = code or (ok and 0 or 4)
        log(string.format(
            "Scan finished (exit %s, %s). Report: %s",
            tostring(exit_code),
            tostring(reason or "exit"),
            report
        ))
    end)
end

local CANDIDATE_TERMS = {
    "workshop",
    "download",
    "installed",
    "mount",
    "travel",
    "servertravel",
    "openlevel",
    "session",
    "lobby",
    "modmap"
}

local function is_candidate(full_name)
    local lower = full_name:lower()
    if not lower:find("function ", 1, true) then
        return false
    end
    for _, term in ipairs(CANDIDATE_TERMS) do
        if lower:find(term, 1, true) then
            return true
        end
    end
    return false
end

local function dump_hook_candidates()
    local output_path = reports_directory() .. "\\ue4ss-hook-candidates.txt"
    local candidates = {}

    log("Walking reflected objects for hook candidates; the game may briefly pause.")
    ForEachUObject(function(object)
        local ok, full_name = pcall(function()
            return object:GetFullName()
        end)
        if ok and full_name and is_candidate(full_name) then
            candidates[#candidates + 1] = full_name
        end
    end)

    table.sort(candidates)
    local output = io.open(output_path, "w")
    if not output then
        log("Could not write diagnostic output: " .. output_path)
        return
    end
    output:write(table.concat(candidates, "\n"))
    output:write("\n")
    output:close()
    log(string.format("Wrote %d hook candidates to %s", #candidates, output_path))
end

RegisterKeyBind(
    Key.F8,
    { ModifierKey.CONTROL, ModifierKey.SHIFT },
    scan_workshop
)
RegisterKeyBind(
    Key.F9,
    { ModifierKey.CONTROL, ModifierKey.SHIFT },
    dump_hook_candidates
)

log("Loaded observe-only prototype. Ctrl+Shift+F8 scans; Ctrl+Shift+F9 dumps hook candidates.")
