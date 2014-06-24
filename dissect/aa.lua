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
-- DISSECTORS (You can probably use the [] tag for C-F)
-- -----------------------------------------------------------------------------
local aa = Proto("aa", "ArcheAge Protocol"); -- Root Dissector [AA]
--------------------------------------------------------------------------------

--------------------------------------------------------------------------------
-- HELPERS
--------------------------------------------------------------------------------
local msg_types = { [0x1202] = "Poll Chat", [0x1302] = "Poll Chat Response" }; -- Could also be a Keep-Alive?
local function type_string(t)
	if (msg_types[t]) then
		return msg_types[t];
	else 
		return "Unknown";
	end
end
--------------------------------------------------------------------------------

-- [AA]
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
		data_len = buf(offset,2):le_uint();
		
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
		t:add(f_len, buf(offset,2), buf(offset,2):le_uint());
		--debug(string.format("Frame #%d @ %d/%d: Reading Length: %d", pkt.number, offset, len, data_len));
		offset = offset + 2;

		-- Server Reply Flag (This could also be part of the message type.)
		t:add(f_srv, buf(offset,1)); 
		--debug(string.format("Frame #%d @ %d/%d: Reading f_srv: %d", pkt.number, offset, len, buf(offset,1)));
		offset = offset + 1;

		-- Message Type
		local msg_type = buf(offset,2):le_uint();
		t:add(f_type, buf(offset,2),  msg_type, string.format("Type: 0x%04x (%s)", msg_type, type_string(msg_type)));
		--debug(string.format("Frame #%d @ %d/%d: Reading Type: %d", pkt.number, offset, len, msg_type));
		offset = offset + 2; -- 2 bytes.

		-- Padding (This is most likely wrong.)
		t:add(f_pad, buf(offset,1));
		offset = offset + 1;

		t:add(f_payload, buf(offset,data_len-4)); -- 4 bytes removed due to: f_srv, f_type and 1 byte padding.
		--debug(string.format("Frame #%d @ %d/%d: Reading Payload: %d", pkt.number, offset, len, (offset-data_len-4)));
		offset = offset + data_len - 4;
	end
end


--------------------------------------------------------------------------------
-- REGISTER
--------------------------------------------------------------------------------
local tcpt = DissectorTable.get( "tcp.port" );
tcpt:add(1239, aa);
-- TODO: There needs to be some extra handling for encryption once/if this is
--       ever reversed.
-- tcp.add(1250), aa); 
--------------------------------------------------------------------------------