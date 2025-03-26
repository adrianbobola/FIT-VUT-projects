-- cpu.vhd: Simple 8-bit CPU (BrainF*ck interpreter)
-- Copyright (C) 2020 Brno University of Technology,
--                    Faculty of Information Technology
-- Author(s): Adrian Bobola - xbobol00
--
library ieee;
use ieee.std_logic_1164.all;
use ieee.std_logic_arith.all;
use ieee.std_logic_unsigned.all;

-- ----------------------------------------------------------------------------
--                        Entity declaration
-- ----------------------------------------------------------------------------
entity cpu is
 port (
   CLK   : in std_logic;  -- hodinovy signal
   RESET : in std_logic;  -- asynchronni reset procesoru
   EN    : in std_logic;  -- povoleni cinnosti procesoru
 
   -- synchronni pamet ROM
   CODE_ADDR : out std_logic_vector(11 downto 0); -- adresa do pameti
   CODE_DATA : in std_logic_vector(7 downto 0);   -- CODE_DATA <- rom[CODE_ADDR] pokud CODE_EN='1'
   CODE_EN   : out std_logic;                     -- povoleni cinnosti
   
   -- synchronni pamet RAM
   DATA_ADDR  : out std_logic_vector(9 downto 0); -- adresa do pameti
   DATA_WDATA : out std_logic_vector(7 downto 0); -- ram[DATA_ADDR] <- DATA_WDATA pokud DATA_EN='1'
   DATA_RDATA : in std_logic_vector(7 downto 0);  -- DATA_RDATA <- ram[DATA_ADDR] pokud DATA_EN='1'
   DATA_WE    : out std_logic;                    -- cteni (0) / zapis (1)
   DATA_EN    : out std_logic;                    -- povoleni cinnosti 
   
   -- vstupni port
   IN_DATA   : in std_logic_vector(7 downto 0);   -- IN_DATA <- stav klavesnice pokud IN_VLD='1' a IN_REQ='1'
   IN_VLD    : in std_logic;                      -- data platna
   IN_REQ    : out std_logic;                     -- pozadavek na vstup data
   
   -- vystupni port
   OUT_DATA : out  std_logic_vector(7 downto 0);  -- zapisovana data
   OUT_BUSY : in std_logic;                       -- LCD je zaneprazdnen (1), nelze zapisovat
   OUT_WE   : out std_logic                       -- LCD <- OUT_DATA pokud OUT_WE='1' a OUT_BUSY='0'
 );
end cpu;

-- ----------------------------------------------------------------------------
--                      Architecture declaration
-- ----------------------------------------------------------------------------
architecture behavioral of cpu is
-- PC register
	signal pc_reg : std_logic_vector (11 downto 0);
	signal pc_inc : std_logic;
	signal pc_dec : std_logic;
	signal pc_ld : std_logic;
	
-- PTR register
	signal ptr_reg : std_logic_vector (9 downto 0);
	signal ptr_inc : std_logic;
	signal ptr_dec : std_logic;
	
-- RAS register bez vnorenych cyklov
	signal ras_reg: std_logic_vector (11 downto 0);
	signal ras_push : std_logic;
	
-- FSM STATE
	type fsm_state is (
			s_start, s_fetch, s_decode,
			s_currentcell_inc, s_currentcell_dec, s_currentcell_dec_end, s_currentcell_inc_mux, s_currentcell_inc_end, s_currentcell_dec_mux,
			s_pointer_inc, s_pointer_dec, 
			s_whilestart, s_whileend, s_whilestart_check, s_whilestart_end, s_whileend_check,
			s_write, s_read, s_read_done, s_write_end,
			s_null);
	signal state : fsm_state := s_start;
	signal next_state : fsm_state;
		
-- MULTIPLEXOR
	signal mux_select : std_logic_vector (1 downto 0) := "00";
	signal mux_out : std_logic_vector (7 downto 0);
----------------------------------------------------------------------------------------------------------------------
--************************************** BEGIN -********************************************************************--
----------------------------------------------------------------------------------------------------------------------	
begin
-- PC proces ---------------------------------------------------------------------------------------------------------
	pc: process (CLK, RESET, pc_inc, pc_dec, pc_ld, ras_reg) is begin
		if (RESET = '1') then
			pc_reg <= "000000000000";
		elsif ((CLK'event) and (CLK = '1')) then
			if (pc_inc = '1') then
				pc_reg <= pc_reg + 1;
			elsif (pc_dec = '1') then
				pc_reg <= pc_reg - 1;
			elsif (pc_ld = '1') then 	-- naèitaj ras_register do pc_registra
				pc_reg <= ras_reg;
			end if;
		end if;
	end process;
	
	CODE_ADDR <= pc_reg;
	
-- RAS proces ---------------------------------------------------------------------------------------------------------
	ras: process (CLK, RESET, pc_reg, ras_push) is begin
		if (RESET = '1') then
			ras_reg <= "000000000000";
		elsif ((CLK'event) and (CLK = '1')) then
			if (ras_push = '1') then
				ras_reg <= pc_reg + 1; -- adresa lavej zatvorky + 1
			end if;
		end if;
	end process;
	
-- PTR proces ---------------------------------------------------------------------------------------------------------
	ptr: process (CLK, RESET, ptr_inc, ptr_dec) is begin
		if (RESET = '1') then
			ptr_reg <= "0000000000";
		elsif ((CLK'event) and (CLK = '1')) then
			if (ptr_inc = '1') then
				ptr_reg <= ptr_reg + 1;
			elsif (ptr_dec = '1') then
				ptr_reg <= ptr_reg - 1;
			end if;
		end if;
	end process;
	
	DATA_ADDR <= ptr_reg;
	OUT_DATA <= DATA_RDATA;
	
-- MULTIPLEXOR ---------------------------------------------------------------------------------------------------------	
	mux: process (CLK, RESET, mux_select) is begin
		if (RESET = '1') then
			mux_out <= "00000000";
		elsif ((CLK'event) and (CLK = '1')) then
			if (mux_select = "00") then
				mux_out <= IN_DATA;
			elsif (mux_select = "01") then
				mux_out <= DATA_RDATA + 1;
			elsif (mux_select = "10") then
				mux_out <= DATA_RDATA - 1;
			else
				mux_out <= "00000000";
			end if;
		end if;
	end process;
	
	DATA_WDATA <= mux_out;

-- STAVY ---------------------------------------------------------------------------------------------------------	
	state_logic: process (CLK, RESET, EN) is begin
		if (RESET = '1') then
			state <= s_start;
		elsif ((CLK'event) and (CLK = '1')) then
			if (EN = '1') then
				state <= next_state;
			end if;
		end if;
	end process;
	
-- FSM proces ---------------------------------------------------------------------------------------------------------		
	fsm: process (state, OUT_BUSY, IN_VLD, CODE_DATA, DATA_RDATA) is begin
		pc_inc <= '0';
		pc_dec <= '0';
		pc_ld <= '0';
		ras_push <= '0';		
		ptr_inc <= '0';
		ptr_dec <= '0';
		CODE_EN <= '0';
		DATA_EN <= '0';
		DATA_WE <= '0';
		IN_REQ <= '0';
		OUT_WE <= '0';
		mux_select <= "00";
		
----------------------------------------- start -> fetch
		if (state = s_start) then 
			next_state <= s_fetch;
----------------------------------------- fetch -> decode
		elsif (state = s_fetch) then
			CODE_EN <= '1';
			next_state <= s_decode;
----------------------------------------- decode -> read symbol
		elsif (state = s_decode) then
			-- < > 
			if (CODE_DATA = X"3E") then
				next_state <= s_pointer_inc;
			elsif (CODE_DATA = X"3C") then
				next_state <= s_pointer_dec;
			-- + -
			elsif (CODE_DATA = X"2B") then
				next_state <= s_currentcell_inc;
			elsif (CODE_DATA = X"2D") then
				next_state <= s_currentcell_dec;
			-- [ ] 
			elsif (CODE_DATA = X"5B") then
				next_state <= s_whilestart;
			elsif (CODE_DATA = X"5D") then
				next_state <= s_whileend;
			-- . ,
			elsif (CODE_DATA = X"2E") then
				next_state <= s_write;
			elsif (CODE_DATA = X"2C") then
				next_state <= s_read;
			-- NULL
			elsif (CODE_DATA = X"00") then
				next_state <= s_null;
			-- OTHERS
			else
				next_state <= s_fetch;
		end if;
		
----------------------------------------------------------------------------------------------------------------------		
----------------------------------------- POINTER INC
		elsif (state = s_pointer_inc) then
			ptr_inc <= '1';
			pc_inc <= '1';
			next_state <= s_fetch;
				
----------------------------------------- POINTER DEC
		elsif (state = s_pointer_dec) then
			ptr_dec <= '1';
			pc_inc <= '1';
			next_state <= s_fetch;
				
----------------------------------------- CURRENT CELL INC
		elsif (state = s_currentcell_inc) then
			DATA_EN <= '1';
			DATA_WE <= '0';
			next_state <= s_currentcell_inc_mux;
			
		elsif (state = s_currentcell_inc_mux) then
			mux_select <= "01";
			next_state <= s_currentcell_inc_end;
			
		elsif (state = s_currentcell_inc_end) then
			DATA_EN <= '1';
			DATA_WE <= '1';
			pc_inc <= '1';
			next_state <= s_fetch;
				
----------------------------------------- CURRENT CELL DEC	
		elsif (state = s_currentcell_dec) then
			DATA_EN <= '1';
			DATA_WE <= '0';
			next_state <= s_currentcell_dec_mux;
			
		elsif (state = s_currentcell_dec_mux) then
			mux_select <= "10";
			next_state <= s_currentcell_dec_end;
			
		elsif (state = s_currentcell_dec_end) then
			DATA_EN <= '1';
			DATA_WE <= '1';
			pc_inc <= '1';
			next_state <= s_fetch;
		
----------------------------------------- WRITE VALUE
		elsif (state = s_write) then
			DATA_EN <= '1';
			DATA_WE <= '0';
			next_state <= s_write_end;
			
		elsif (state = s_write_end) then
			if (OUT_BUSY = '1') then
				DATA_EN <= '1';
				DATA_WE <= '0';
				next_state <= s_write_end;
			else
				OUT_WE <= '1';
				pc_inc <= '1';
				next_state <= s_fetch;
			end if;
				
----------------------------------------- READ VALUE	
		elsif (state = s_read) then
			IN_REQ <= '1';
			mux_select <= "00";
			next_state <= s_read_done;
			
		elsif (state = s_read_done) then
			if (IN_VLD /= '1') then
				IN_REQ <= '1';
				mux_select <= "00";
				next_state <= s_read_done;
			else
				DATA_EN <= '1';
				DATA_WE <= '1';
				pc_inc <= '1';
				next_state <= s_fetch;
			end if;

----------------------------------------- WHILE START
		elsif (state = s_whilestart) then
			pc_inc <= '1';
			ras_push <= '1';
			DATA_EN <= '1';
			DATA_WE <= '0'; --chceme cist z pameti
			next_state <= s_whilestart_check;
			
		elsif (state = s_whilestart_check) then
			if (DATA_RDATA /= "0000000") then
				next_state <= s_fetch; -- ram[ptr] != 0
			else
			   CODE_EN <= '1';
				next_state <= s_whilestart_end;
			end if;
			
		elsif (state = s_whilestart_end) then -- ram[ptr] == 0
			if (CODE_DATA = X"5D") then -- end while cycle
				next_state <= s_fetch;
			else
				pc_inc <= '1';
			end if;
			CODE_EN <= '1';
			next_state <= s_whilestart_end;
				
----------------------------------------- WHILE END		
		elsif (state = s_whileend) then
			DATA_EN <= '1';
			DATA_WE <= '0';
			next_state <= s_whileend_check;
			
		elsif (state = s_whileend_check) then
			if (DATA_RDATA = "0000000") then --ram[PTR] == 0
				pc_inc <= '1';
				next_state <= s_fetch;
			else
				pc_ld <= '1';
				next_state <= s_fetch;
			end if;		

----------------------------------------- NULL
		elsif (state = s_null) then
			next_state <= s_null;

		else
			next_state <= s_fetch;
		end if;
	end process;
end behavioral;
