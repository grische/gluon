#!/usr/bin/lua

-- Apply Batman-V throughput_override to tunnel batadv hardifs (mesh-vpn,
-- etc.) based on the WAN interface's sysfs link speed. Invoked from the
-- hotplug.d/iface wrapper, which has already filtered $ACTION and
-- $INTERFACE.
--
-- Speed-less hardifs are targeted via tunnel_hardifs(): in practice
-- mesh-vpn, the VXLAN-over-WireGuard tunnel. VXLAN-over-Ethernet
-- wired-mesh hardifs (vx_mesh_uplink/vx_mesh_other) transparently report
-- their lower device's speed via sysfs, so on DSA batman-V reads them
-- natively and they are left alone. The exception is swconfig, where the
-- lower device is the CPU-side VLAN netdev and its sysfs speed is the CPU
-- port's, not the front-panel port's -- there correct_swconfig_wired_mesh()
-- force-applies the accurate per-port speed from gluon.ethernet.
--
-- Triggers:
--   ifup/ifdown wan/wan6/cellular/cellular_4 -> iterate tunnel hardifs
--   ifup mesh_vpn                            -> wait for bat0 registration,
--                                               apply to mesh-vpn only

local ethernet     = require 'gluon.ethernet'
local uci          = require 'simple-uci'
local util         = require 'gluon.util'
local posix_stat   = require 'posix.sys.stat'
local posix_syslog = require 'posix.syslog'
local posix_unistd = require 'posix.unistd'

local ACTION    = os.getenv('ACTION')    or ''
local INTERFACE = os.getenv('INTERFACE') or ''
local PERIODIC  = os.getenv('GLUON_BATADV_TPO_PERIODIC') == '1'
local TAG       = 'gluon-batadv-tpo'

posix_syslog.openlog(TAG, 0, posix_syslog.LOG_DAEMON)

local function log(msg)
	posix_syslog.syslog(posix_syslog.LOG_INFO,
		INTERFACE .. ' ' .. ACTION .. ': ' .. msg)
end

local function warn(msg)
	posix_syslog.syslog(posix_syslog.LOG_WARNING,
		INTERFACE .. ' ' .. ACTION .. ': ' .. msg)
end

-- Batman-V only. /sys/module/.../routing_algo is a terse one-liner
-- ("BATMAN_V" or "BATMAN_IV"); avoids parsing batctl's verbose output.
local routing_algo = util.readfile('/sys/module/batman_adv/parameters/routing_algo')
if not routing_algo or util.trim(routing_algo) ~= 'BATMAN_V' then
	os.exit(0)
end

-- Sysfs link speed in kbit/s; nil if unknown or non-positive.
local function sysfs_speed_kbit(iface)
	local s = util.readfile('/sys/class/net/' .. iface .. '/speed')
	if not s then return nil end
	local n = tonumber(util.trim(s))
	if not n or n <= 0 then return nil end
	return n * 1000
end

local function is_wireless(iface)
	return posix_stat.stat('/sys/class/net/' .. iface .. '/phy80211') ~= nil
end

-- Collect batadv hardifs (= bat0's lower_* symlinks) that need an
-- override: not wireless, not the internal dummy, no native sysfs speed.
local function tunnel_hardifs()
	local result = {}
	for _, link in ipairs(util.glob('/sys/class/net/bat0/lower_*')) do
		local iface = link:match('/lower_(.+)$')
		-- primary0 is the dummy hardif that carries bat0's MAC -- it has
		-- no neighbours and never carries traffic, so an override there
		-- would be cosmetic noise.
		--
		-- The VXLAN wired-mesh hardifs (vx_mesh_uplink over br-wan,
		-- vx_mesh_other over the wired mesh port) are *not* matched here:
		-- a VXLAN-over-Ethernet netdev transparently reports its lower
		-- device's link speed via sysfs, so sysfs_speed_kbit() is non-nil
		-- for them. On DSA that speed is correct and batman-V reads it
		-- natively; the swconfig case (where it's the CPU-port speed) is
		-- corrected by correct_swconfig_wired_mesh(). Only speed-less
		-- tunnels (mesh-vpn, the VXLAN-over-WireGuard) fall through to here
		-- and need an override.
		if iface
			and iface ~= 'primary0'
			and not is_wireless(iface)
			and not sysfs_speed_kbit(iface) then
			result[#result + 1] = iface
		end
	end
	return result
end

-- Wait up to ~30s for the hardif to be registered with batadv. The
-- 30-gluon-mesh-batman-adv post-setup.d issues an async ubus renew that
-- adds the hardif; on slow boots under ubus contention this can lag
-- past 10s. Only used in the mesh_vpn ifup branch.
local function wait_for_hardif(iface)
	for _ = 1, 30 do
		if posix_stat.stat('/sys/class/net/bat0/lower_' .. iface) then
			return true
		end
		posix_unistd.sleep(1)
	end
	return false
end

-- Ceiling from operator-configured bandwidth_limit (kbit/s in UCI),
-- mesh-vpn only. min() is intentional: it handles the typical asymmetric
-- DSL case (egress is the bottleneck) and conservatively bounds the
-- batman-V routing decision in both directions.
local function bandwidth_limit_cap()
	local c = uci.cursor()
	if not c:get_bool('gluon', 'mesh_vpn', 'limit_enabled') then return nil end
	local lin = tonumber(c:get('gluon', 'mesh_vpn', 'limit_ingress'))
	local leg = tonumber(c:get('gluon', 'mesh_vpn', 'limit_egress'))
	if not lin or not leg or lin <= 0 or leg <= 0 then return nil end
	return math.min(lin, leg)
end

-- Min carrier-up link speed (kbit/s) across the given netdevs, or nil if
-- none reports a usable speed (conservative bottleneck when several are
-- up). Per-port speed is queried via gluon.ethernet.get_link_speed_kbit,
-- which handles swconfig (per-port via /etc/board.json + `swconfig dev
-- <sw> port <N> get link`) and DSA (sysfs is authoritative) transparently.
-- Skips wireless (sysfs speed is meaningless there; mesh radios use ELP)
-- and netdevs that don't exist yet (UCI-configured but not created, e.g.
-- USB tethers).
local function min_link_speed_kbit(ifaces)
	local min_speed
	for _, iface in ipairs(ifaces) do
		if not is_wireless(iface)
			and posix_stat.stat('/sys/class/net/' .. iface) then
			local carrier = util.readfile('/sys/class/net/' .. iface .. '/carrier')
			if carrier and util.trim(carrier) == '1' then
				local speed = ethernet.get_link_speed_kbit(iface)
				if speed and (not min_speed or speed < min_speed) then
					min_speed = speed
				end
			end
		end
	end
	return min_speed
end

-- Active uplink throughput in kbit/s: min across every carrier-up gluon
-- role=uplink interface. nil if none reports a usable speed.
--
-- Gluon's "uplink anywhere" feature lets several physical-port ifaces
-- carry role='uplink' (e.g. on the AVM FRITZ!Box 4020 both the dedicated
-- WAN port and the LAN ports are uplinks, bridged together into br-wan).
-- Moving the cable between such ports keeps the wan UCI iface 'up' so
-- no ifdown/ifup hotplug fires; the worker still reads the right speed
-- by walking the role list rather than a single sysconfig.wan_ifname.
--
-- Known limitation: intra-bridge cable moves are not auto-detected at
-- the netifd hotplug layer (no ifup/ifdown fires while at least one
-- bridge member retains carrier). The micrond entry at
-- /usr/lib/micron.d/gluon-mesh-batman-adv-tunnel-throughput re-evaluates
-- every 10 minutes as a fallback.
local function active_uplink_speed_kbit()
	return min_link_speed_kbit(util.get_role_interfaces(uci.cursor(), 'uplink'))
end

-- Throughput of the dedicated wired node-to-node mesh ports -- role=mesh
-- but not role=uplink -- backing the vx_mesh_other hardif (mesh-on-LAN).
-- The role split mirrors 210-interface-mesh: ifaces that are mesh *and*
-- uplink go into vx_mesh_uplink, the rest into vx_mesh_other. Only used
-- for the swconfig correction below (on DSA the vxlan reports the real
-- port speed natively, so no override is needed). nil if no such port is
-- carrier-up with a readable speed.
local function mesh_other_speed_kbit()
	local cursor = uci.cursor()
	local is_uplink = {}
	for _, iface in ipairs(util.get_role_interfaces(cursor, 'uplink')) do
		is_uplink[iface] = true
	end
	local mesh_ifaces = {}
	for _, iface in ipairs(util.get_role_interfaces(cursor, 'mesh')) do
		if not is_uplink[iface] then
			mesh_ifaces[#mesh_ifaces + 1] = iface
		end
	end
	return min_link_speed_kbit(mesh_ifaces)
end

-- Compute the override to apply now. Returns kbit/s on ifup if an active
-- uplink has a readable link speed, 0 on ifdown, or nil if we should
-- leave whatever is set alone (no readable uplink -> no good answer).
local function compute_override(hardif)
	if ACTION == 'ifdown' then return 0 end
	local speed = active_uplink_speed_kbit()
	if not speed then
		-- On a real hotplug event this one-off warning explains why no
		-- override was set. On the periodic (cron) tick it would just
		-- repeat every 10 minutes on nodes whose only uplink is wireless
		-- or a USB tether, so stay quiet there.
		if not PERIODIC then
			warn(hardif .. ': no active uplink with readable link speed; leaving default')
		end
		return nil
	end
	if hardif == 'mesh-vpn' then
		local cap = bandwidth_limit_cap()
		if cap and cap < speed then
			log('capping ' .. speed .. ' kbit/s at bandwidth_limit ' .. cap .. ' kbit/s')
			speed = cap
		end
	end
	return speed
end

-- Read the current throughput_override for a hardif and return it as
-- kbit/s. batctl prints e.g. "0.0 MBit" or "1000.0 MBit"; we extract
-- the first numeric token and multiply by 1000. Returns nil on error
-- (hardif missing, batctl unavailable).
local function read_current_override_kbit(hardif)
	local f = io.popen('batctl hardif ' .. hardif
		.. ' throughput_override 2>/dev/null')
	if not f then return nil end
	local out = f:read('*a') or ''
	f:close()
	local mbit = tonumber((out:match('([%d%.]+)')))
	if not mbit then return nil end
	return math.floor(mbit * 1000 + 1/2)
end

-- Apply override only if the kernel's actual value differs from what
-- we'd set. Reading the live value back from batctl (rather than
-- caching our last write) keeps us correct across external
-- modifications -- an operator-set value or a concurrent writer -- at
-- the cost of one extra ~20ms batctl exec per fire, and avoids
-- redundant writes and their syslog noise when nothing has changed.
local function apply_override(hardif, value)
	if value == nil then return end
	-- batman_adv stores throughput_override in 100-kbit/s units (0.1 Mbit
	-- granularity), so writes are quantized to the nearest 100 kbit. Round
	-- the target the same way before comparing, otherwise non-whole-Mbit
	-- values (e.g. an operator bandwidth_limit of 512 kbit, stored as 500)
	-- would never equal the read-back value and we'd rewrite every tick.
	-- (value + 50) / 100 rather than value / 100 + 0.5: a 0.5 literal is
	-- minified by luasrcdiet to '.5', which OpenWrt's Lua 5.1 tonumber()
	-- rejects, failing the build (see also the 1/2 above).
	local target = math.floor((value + 50) / 100) * 100
	local current = read_current_override_kbit(hardif)
	if current == target then return end

	local arg = string.format('%dkbit', target)
	local rc = os.execute('batctl hardif ' .. hardif
		.. ' throughput_override ' .. arg .. ' 2>/dev/null')
	if rc ~= 0 then
		warn(hardif .. ': batctl throughput_override ' .. arg .. ' failed')
		return
	end
	log(hardif .. ': throughput_override ' ..
		(current and (current .. ' kbit') or '?') .. ' -> ' .. arg)
end

-- Is a hardif registered with batadv (= present as a bat0 lower)?
local function hardif_registered(iface)
	return posix_stat.stat('/sys/class/net/bat0/lower_' .. iface) ~= nil
end

-- swconfig wired-mesh correction.
--
-- A VXLAN wired-mesh hardif (vx_mesh_uplink over br-wan, vx_mesh_other
-- over the wired mesh port) transparently inherits its lower device's
-- ethtool/sysfs speed. On DSA that lower is the real switch port, so
-- batman-V reads the correct speed natively and we leave it alone -- it
-- is deliberately not matched by tunnel_hardifs(). On swconfig the lower
-- is the CPU-side VLAN netdev (e.g. eth0.1), whose sysfs speed is always
-- the CPU port's (typically 1G) regardless of which front-panel port the
-- cable is in, so batman-V mis-rates the wired mesh link. There
-- gluon.ethernet.get_link_speed_kbit() recovers the real per-port speed,
-- so on swconfig only, force the override from it.
--
-- Like the uplink path this is blind to intra-switch cable moves at the
-- hotplug layer (no ifup/ifdown fires); the 10-minute micrond re-run is
-- the safety net. ACTION is ignored on purpose: the wired mesh link is
-- independent of the wan iface, so a wan ifdown must not clear it.
local function correct_swconfig_wired_mesh()
	if ethernet.get_switch_type() ~= 'swconfig' then return end
	if hardif_registered('vx_mesh_uplink') then
		apply_override('vx_mesh_uplink', active_uplink_speed_kbit())
	end
	if hardif_registered('vx_mesh_other') then
		apply_override('vx_mesh_other', mesh_other_speed_kbit())
	end
end

-- --- main ---

-- INTERFACE=mesh_vpn fires on both ifup and ifdown. On ifdown the batadv
-- hardif is being removed by netifd; no point waiting or clearing.
-- The netdev "mesh-vpn" (hyphen) is named verbatim by gluon-mesh-vpn-core
-- (500-mesh-vpn) regardless of provider, so the UCI->hardif mapping is
-- stable.
if INTERFACE == 'mesh_vpn' then
	if ACTION ~= 'ifup' then os.exit(0) end
	if not wait_for_hardif('mesh-vpn') then
		warn('mesh-vpn not registered with batadv after 30s; skipping')
		os.exit(0)
	end
	apply_override('mesh-vpn', compute_override('mesh-vpn'))
	os.exit(0)
end

-- wan / wan6 / cellular / cellular_4: iterate currently-registered hardifs.
for _, hardif in ipairs(tunnel_hardifs()) do
	apply_override(hardif, compute_override(hardif))
end

-- On swconfig, additionally correct the wired-mesh hardifs whose sysfs
-- speed reflects the CPU port rather than the real front-panel port.
correct_swconfig_wired_mesh()
