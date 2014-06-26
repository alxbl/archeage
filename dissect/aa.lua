-- Copyright (c) 2014 Alexandre Beaulieu <alxbl03@gmail.com>

-- aa.lua is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.

-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.

-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

-- Disclaimer: I am Lua noob.

--------------------------------------------------------------------------------
-- "Globals" & TOC
-- -----------------------------------------------------------------------------
local msg_handlers = {}; -- Type -> Dissector
local msg_types = {};    -- Type -> String

local aa = Proto("aa", "ArcheAge Protocol"); -- [aa]
local aa_chat = Proto("aa.chat", "Chat Message"); -- [aa.chat]

-- Some Helpers
local function t2s(t) -- Type to String
	if (msg_types[t]) then
		return msg_types[t];
	else 
		return "Unknown";
	end
end
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- [aa] ROOT DISSECTOR
--------------------------------------------------------------------------------
local f_len  = ProtoField.uint16("aa.len", "Length", base.DEC);
local f_srv  = ProtoField.bool("aa.reply", "Server Reply"); -- 0xdd
local f_type = ProtoField.uint16("aa.type", "Message Type", base.HEX);
local f_pad  = ProtoField.uint8("aa.pad", "Padding");
local f_payload = ProtoField.bytes("aa.data", "Payload"); -- TODO: Chain Dissectors to work on the payload.

aa.fields = {f_len, f_srv, f_type, f_pad, f_payload};

-- Base Packet Structure -------------------------------------------------------
---+----------------+------------+--------------+----------+-------------------+
-- |    2 bytes     |   1 byte   |    2 bytes   |  1 byte  | <Len - 6> bytes   |
-- +----------------+------------+--------------+----------+-------------------+
-- | Payload Length | Reply Flag | Message Type | Padding? | Payload           |
-- +----------------+------------+--------------+----------+-------------------+
-- Note: Padding is most likely wrong. 
--       Reply Flag is also too fishy, but so far it works 100% of the time.
-- TODO: <Padding> Could be encryption flag too? but not always consistent.
function aa.dissector(buf, pkt, tree)
	local len = buf:len(); -- Length of the TCP payload.
	local data_len = 0;    -- Does not include the length bytes.
	local offset = 0;      -- Used to handle multiple PDUs in a single TCP frame.

	while (offset < len) do
		if (len < 2) then
			-- Need one more segment to read a PDU. Very unlikely to happen.
			info(string.format("Frame #%d @ %d/%d: Not enough data to read a PDU. Desegmenting one more segment.", pkt.number, offset, len));
			pkt.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
			pkt.desegment_offset = 0
			return;
		end

		-- ArcheAge transmits in little endian. So much for convention.
		data_len = buf(offset, 2):le_uint();
		
		local remaining = len - offset - 2;
		if (data_len > remaining) then -- We want the remaining length of the segment.
			pkt.desegment_len = data_len - remaining;
			pkt.desegment_offset = 0 -- Reparse these bytes along with the extra data requested.
			info(string.format("Frame #%d @ %d/%d: PDU is bigger than current segment. Desegmenting %d extra bytes.", pkt.number, offset, len, len-offset));
			return;
		end

		-- Packet has all the data.
		pkt.cols.protocol	= "AA";

		-- Root
		local t = tree:add(aa, buf(offset, data_len+2), "PDU"); -- Include the length as part of the root.

		-- Payload Length without length bytes.
		t:add(f_len, buf(offset, 2), buf(offset, 2):le_uint());
		offset = offset + 2;

		-- Server Reply Flag (This could also be part of the message type.)
		t:add(f_srv, buf(offset, 1)); 
		offset = offset + 1;

		-- Message Type
		local msg_type = buf(offset, 2):le_uint();
		t:add(f_type, buf(offset, 2),  msg_type, string.format("Type: 0x%04x (%s)", msg_type, t2s(msg_type)));
		offset = offset + 2; -- 2 bytes.

		-- Padding (This is most likely wrong.)
		t:add(f_pad, buf(offset, 1));
		offset = offset + 1;

		-- Dissect the Payload
		local payload = buf(offset, data_len-4); -- 4 bytes removed due to: f_srv, f_type and 1 byte padding.
		if (msg_handlers[msg_type]) then
			local d = msg_handlers[msg_type]
			d:call(payload:tvb(), pkt, t);
		else
			t:add(f_payload, payload); -- Unknown Payload.
		end 
		offset = offset + data_len - 4; -- Skip to the next PDU.
	end
end

--------------------------------------------------------------------------------
-- [aa.chat] CHAT DISSECTOR
--------------------------------------------------------------------------------
msg_types[0x1202] = "Ping";
msg_types[0x1302] = "Pong";

msg_types[0xcc01] = "Chat";

aa_chat.fields = {};
local f_chat_unknown  = ProtoField.bytes("aa.chat.unknown", "Unknown"); table.insert(aa_chat.fields, f_chat_unknown);-- TODO: Reverse
local f_chat_nicklen  = ProtoField.uint16("aa.chat.nick.len", "Nickname Length"); table.insert(aa_chat.fields, f_chat_nicklen);
local f_chat_nickname = ProtoField.string("aa.chat.nick", "Nickname"); table.insert(aa_chat.fields, f_chat_nickname);
local f_chat_msglen   = ProtoField.uint16("aa.chat.msg.len", "Message Length"); table.insert(aa_chat.fields, f_chat_msglen);
local f_chat_msg      = ProtoField.string("aa.chat.msg", "Message"); table.insert(aa_chat.fields, f_chat_msg);
local f_chat_epilogue = ProtoField.bytes("aa.chat.epilogue", "Unknown"); table.insert(aa_chat.fields, f_chat_epilogue);-- TODO: Reverse

function aa_chat.dissector(buf, pkt, tree)
	local t = tree:add(aa_chat, buf());
	local offset = 0;
	
	-- 22 non-reversed bytes
	t:add(f_chat_unknown, buf(offset, 21)); 
	offset = offset + 21;

	-- Nickname Length
	local nick_len = buf(offset, 2):le_uint();
	t:add(f_chat_nicklen, buf(offset, 2), nick_len);
	offset = offset + 2;
	
	-- Nickname
	t:add(f_chat_nickname, buf(offset, nick_len));
	offset = offset + nick_len;

	-- Message Length
	local msg_len = buf(offset, 2):le_uint();
	t:add(f_chat_msglen, buf(offset, 2), msg_len);
	offset = offset + 2;
	
	-- Message
	t:add(f_chat_msg, buf(offset, msg_len));
	offset = offset + msg_len;

	-- Non-reversed Epilogue
	t:add(f_chat_epilogue, buf(offset, buf:len()-offset));
end
msg_handlers[0xcc01] = aa_chat.dissector;

--------------------------------------------------------------------------------
-- REGISTER
--------------------------------------------------------------------------------
local tcpt = DissectorTable.get( "tcp.port" );
tcpt:add(1239, aa);
-- TODO: There needs to be some extra handling for encryption once/if this is
--       ever reversed.
-- tcp.add(1250), aa); 
--------------------------------------------------------------------------------