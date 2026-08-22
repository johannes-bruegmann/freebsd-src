--
-- SPDX-License-Identifier: BSD-2-Clause
--
-- Copyright (c) 2015 Pedro Souza <pedrosouza@freebsd.org>
-- Copyright (c) 2018 Kyle Evans <kevans@FreeBSD.org>
-- All rights reserved.
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
--
-- THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
-- ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
-- FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
-- OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
-- HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
-- LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
-- OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-- SUCH DAMAGE.
--

local core = require("core")
local screen = require("screen")

-- Registered by common/interp_lua.c. pcall, so that a stock loader
-- binary paired with this file cannot break the boot: match() then
-- stays locked instead of falling back to a plaintext comparison.
local ok_hash, hash = pcall(require, "hash")
if not ok_hash then
	hash = nil
end

local password = {}

local INCORRECT_PASSWORD = "loader: incorrect password"
-- Asterisks as a password mask
local show_password_mask = false
local twiddle_chars = {"/", "-", "\\", "|"}
local screen_setup = false

local function setup_screen()
	screen.clear()
	screen.defcursor()
	screen_setup = true
end

-- Module exports
function password.read(prompt_length)
	local str = ""
	local twiddle_pos = 1

	local function draw_twiddle()
		printc(twiddle_chars[twiddle_pos])
		-- Reset cursor to just after the password prompt
		screen.setcursor(prompt_length + 2, screen.default_y)
		twiddle_pos = (twiddle_pos % #twiddle_chars) + 1
	end

	-- Space between the prompt and any on-screen feedback
	printc(" ")
	while true do
		local ch = io.getchar()
		if ch == core.KEY_ENTER then
			break
		end
		if ch == core.KEY_BACKSPACE or ch == core.KEY_DELETE then
			if #str > 0 then
				if show_password_mask then
					printc("\008 \008")
				else
					draw_twiddle()
				end
				str = str:sub(1, #str - 1)
			end
		else
			if show_password_mask then
				printc("*")
			else
				draw_twiddle()
			end
			str = str .. string.char(ch)
		end
	end
	return str
end

function password.check()
	-- pwd is optionally supplied if we want to check it
	-- A *_sha256 variable wins over its plaintext counterpart.
	-- With neither set there is nothing to check, which is the
	-- GELI case: doPrompt is called there without a secret.
	local function match(entered, pwd, pwd_hash)
		if pwd_hash ~= nil then
			-- Without the module we cannot verify, so stay
			-- locked rather than accept plaintext.
			if hash == nil then
				return false
			end
			return hash.sha256(entered):hexdigest() ==
			    pwd_hash:lower()
		end
		return pwd == nil or pwd == entered
	end

	local function doPrompt(prompt, pwd, pwd_hash)
		local attempts = 1

		local function clear_incorrect_text_prompt()
			printc("\r" .. string.rep(" ", #INCORRECT_PASSWORD))
		end

		if not screen_setup then
			setup_screen()
		end

		while true do
			if attempts > 1 then
				clear_incorrect_text_prompt()
			end
			screen.defcursor()
			printc(prompt)
			local read_pwd = password.read(#prompt)
			if match(read_pwd, pwd, pwd_hash) then
				-- Clear the prompt + twiddle
				printc(string.rep(" ", #prompt + 5))
				return read_pwd
			end
			printc("\n" .. INCORRECT_PASSWORD)
			attempts = attempts + 1
			loader.delay(3*1000*1000)
		end
	end
	local function compare(prompt, pwd, pwd_hash)
		if pwd == nil and pwd_hash == nil then
			return
		end
		doPrompt(prompt, pwd, pwd_hash)
	end

	-- The loader publishes what it MEASURED (loader.trust.bootlock.passed,
	-- .failed, .skipped); the policy lives here. Which witnesses you
	-- insist on is a judgement, and this file is on the signed
	-- medium, so it changes without rebuilding the loader.
	--
	-- loader_trust_require, in loader.conf:
	--   unset          only a FAILURE gates (and see below)
	--   "all"          every witness must have run
	--   "A,B,C"        exactly these must be in passed
	--
	-- A list beats "all" once a witness is deliberately asleep:
	-- "all" would then demand the passphrase forever.
	--
	-- Asked before the GELI passphrase, i.e. first of all, and the
	-- reason goes into the prompt TEXT because doPrompt calls
	-- setup_screen(), which clears anything printed before it.
	local trust_hash = loader.getenv("loader_trust_password_sha256")
	if trust_hash ~= nil then
		local failed = loader.getenv("loader.trust.bootlock.failed") or ""
		local passed = loader.getenv("loader.trust.bootlock.passed") or ""
		local skipped = loader.getenv("loader.trust.bootlock.skipped") or ""
		-- Not named `require`: that is the module loader.
		local mode = loader.getenv("loader_trust_require")
		-- An empty failed list next to an empty passed list means
		-- nothing was checked, and silence is not trust. An absent
		-- variable says the loader predates the feature: same case.
		local why
		if failed ~= "" then
			why = "failed=" .. failed
		elseif passed == "" then
			why = "nothing checked"
		elseif mode == "all" and skipped ~= "" then
			why = "skipped=" .. skipped
		elseif mode ~= nil and mode ~= "all" then
			-- Every required name must appear in passed. Commas on
			-- both sides make the match unambiguous, so SecureBoot
			-- cannot satisfy a requirement for SecureBootKeys.
			local haystack = "," .. passed .. ","
			for name in mode:gmatch("[^,%s]+") do
				if not haystack:find("," .. name .. ",", 1, true) then
					why = "missing=" .. name
					break
				end
			end
		end
		if why ~= nil then
			compare("Platform trust (" .. why ..
			    ") -- passphrase:", nil, trust_hash)
			-- doPrompt() runs setup_screen() only ONCE, so the next
			-- prompt is drawn at the same position without a clear.
			-- This prompt is long and the GELI one is short, so its
			-- tail would stay visible behind it. Observed 2026-08-17.
			screen.clear()
			screen.defcursor()
		end
	end

	local boot_pwd = loader.getenv("bootlock_password")
	local boot_pwd_hash = loader.getenv("bootlock_password_sha256")
	compare("Bootlock password:", boot_pwd, boot_pwd_hash)

	local geli_prompt = loader.getenv("geom_eli_passphrase_prompt")
	if geli_prompt ~= nil and geli_prompt:lower() == "yes" then
		local passphrase = doPrompt("GELI Passphrase:")
		loader.setenv("kern.geom.eli.passphrase", passphrase)
	end

	local pwd = loader.getenv("password")
	local pwd_hash = loader.getenv("password_sha256")
	if pwd ~= nil or pwd_hash ~= nil then
		core.autoboot()
		loader.setenv("autoboot_delay", "NO")
		-- The autoboot sequence was interrupted, so we'll need to
		-- prompt for a password.  Put the screen back into a known
		-- good state, otherwise we're drawing back a couple lines
		-- in the middle of other text.
		setup_screen()
	end
	compare("Loader password:", pwd, pwd_hash)
end

return password
