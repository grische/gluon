local util = require 'gluon.util'
local unistd = require 'posix.unistd'
local dirent = require 'posix.dirent'
local uci = require('simple-uci').cursor()

local M = {}

local function has_devtype(iface_dir, devtype)
	return util.file_contains_line(iface_dir..'/uevent', 'DEVTYPE='..devtype)
end

local function is_physical(iface_dir)
	return unistd.access(iface_dir .. '/device') == 0
end

local function is_swconfig()
	local has = false

	uci:foreach("network", "switch", function()
		has = true
	end)

	uci:foreach("network", "switch_vlan", function()
		has = true
	end)

	return has
end

local function interfaces_raw()
	local eth_ifaces = {}
	local ifaces_dir = '/sys/class/net/'

	for iface in dirent.files(ifaces_dir) do
		if iface ~= '.' and iface ~= '..' then
			local iface_dir = ifaces_dir .. iface
			if is_physical(iface_dir) and not has_devtype(iface_dir, 'wlan') then
				table.insert(eth_ifaces, iface)
			end
		end
	end

	return eth_ifaces
end

-- In comparison to interfaces_raw, this skips non-DSA ports on DSA devices,
-- as for ex. hap ac² has a special eth0 that shouldn't be touched
function M.interfaces()
	local intfs = interfaces_raw()

	if M.get_switch_type() == 'dsa' then
		local new_intfs = {}
		for _, intf in ipairs(intfs) do
			if has_devtype('/sys/class/net/' .. intf, 'dsa') then
				table.insert(new_intfs, intf)
			end
		end

		return new_intfs
	end

	return intfs
end

function M.is_vlan(intf)
	return has_devtype('/sys/class/net/' .. intf, 'vlan')
end

function M.get_switch_type()
	if is_swconfig() then
		return 'swconfig'
	end

	for _, intf in ipairs(interfaces_raw()) do
		if has_devtype('/sys/class/net/' .. intf, 'dsa') then
			return 'dsa'
		end
	end

	return 'none'
end

-- Read /sys/class/net/<iface>/speed; returns kbit/s or nil for
-- unknown/non-positive. Authoritative on DSA + physical NICs, but on a
-- swconfig CPU-side VLAN netdev reports the CPU port's speed, not the
-- physical port's. Callers wanting per-port accuracy on swconfig should
-- use M.get_link_speed_kbit instead.
local function sysfs_speed_kbit(iface)
	local s = util.readfile('/sys/class/net/' .. iface .. '/speed')
	if not s then return nil end
	local n = tonumber(util.trim(s))
	if not n or n <= 0 then return nil end
	return n * 1000
end

-- Returns the effective link speed of an Ethernet-shaped netdev in
-- kbit/s, or nil if it's unknown (no carrier, or kernel doesn't
-- expose it).
--
-- On DSA switches and physical NICs, /sys/class/net/<iface>/speed is
-- authoritative -- each port is its own netdev. On swconfig switches
-- the CPU-side VLAN netdev's sysfs always reports the CPU port's
-- speed (typically 1G) regardless of which front-panel port the cable
-- is in. To get the real per-port speed on swconfig, derive the
-- (switch, ports) tuple from /etc/board.json's iface->roles mapping
-- and query `swconfig dev <sw> port <N> get link` per port. Return
-- min across carrier-up physical ports (the bottleneck).
--
-- Refuses to lie: if no carrier-up port can be found, returns nil so
-- callers can decline to derive a routing metric from this value.
function M.get_link_speed_kbit(iface)
	if M.get_switch_type() ~= 'swconfig' then
		return sysfs_speed_kbit(iface)
	end

	-- swconfig only applies to interfaces declared as role-devices in
	-- board.json. Dedicated netdevs (e.g. a separate WAN port not
	-- routed through the switch) still have accurate sysfs speed.
	local json = require 'jsonc'
	local board = json.load('/etc/board.json')
	if not board or not board.switch then
		return sysfs_speed_kbit(iface)
	end

	for sw_name, sw in pairs(board.switch) do
		for _, role in ipairs(sw.roles or {}) do
			if role.device == iface then
				local min_speed
				for port_spec in (role.ports or ''):gmatch('%S+') do
					-- Skip CPU port(s); tagged-CPU suffix is 't'.
					if not port_spec:match('t$') then
						local port_num = port_spec:match('^(%d+)')
						if port_num then
							-- swconfig output:
							--   "port:N link:up speed:Xbase... ..."
							--   "port:N link:down"
							local cmd = string.format(
								'swconfig dev %s port %s get link 2>/dev/null',
								sw_name, port_num)
							local out = util.exec(cmd) or ''
							if not out:find('link:down') then
								local s = out:match('speed:(%d+)base')
								local n = s and tonumber(s)
								if n and n > 0
									and (not min_speed or n < min_speed) then
									min_speed = n
								end
							end
						end
					end
				end
				return min_speed and min_speed * 1000 or nil
			end
		end
	end

	-- iface isn't in any switch role; treat as direct netdev.
	return sysfs_speed_kbit(iface)
end

return M
