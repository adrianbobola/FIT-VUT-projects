-- fsm.vhd: Finite State Machine
-- Author(s): 
--
library ieee;
use ieee.std_logic_1164.all;
-- ----------------------------------------------------------------------------
--                        Entity declaration
-- ----------------------------------------------------------------------------
entity fsm is
port(
   CLK         : in  std_logic;
   RESET       : in  std_logic;

   -- Input signals
   KEY         : in  std_logic_vector(15 downto 0);
   CNT_OF      : in  std_logic;

   -- Output signals
   FSM_CNT_CE  : out std_logic;
   FSM_MX_MEM  : out std_logic;
   FSM_MX_LCD  : out std_logic;
   FSM_LCD_WR  : out std_logic;
   FSM_LCD_CLR : out std_logic
);
end entity fsm;

-- ----------------------------------------------------------------------------
--                      Architecture declaration
-- ----------------------------------------------------------------------------
architecture behavioral of fsm is
   type t_state is (TEST_START, TEST_ERROR, TEST_1, TEST_17, TEST_172, TEST_1726, TEST_17263, TEST_172639, TEST_1726395, TEST_17263950, TEST_172639504, TEST_1726395044, TEST_1726396, TEST_17263960, TEST_172639603, TEST_1726396035, TEST_17263960352, MESSAGE_ERR, MESSAGE_OK, FINISH);
   signal present_state, next_state : t_state;

begin
-- -------------------------------------------------------
sync_logic : process(RESET, CLK)
begin
   if (RESET = '1') then
      present_state <= TEST_START;
   elsif (CLK'event AND CLK = '1') then
      present_state <= next_state;
   end if;
end process sync_logic;

-- -------------------------------------------------------
next_state_logic : process(present_state, KEY, CNT_OF)
begin
   case (present_state) is
   -- - - - - - - - - - - - - - - - - - - - - - -
   when TEST_START =>
      next_state <= TEST_START;
      if (KEY(1) = '1') then
         next_state <= TEST_1; 
      elsif (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
	when TEST_1=>
      next_state <= TEST_1;
      if (KEY(7) = '1') then
         next_state <= TEST_17; 
      elsif (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
		when TEST_17=>
      next_state <= TEST_17;
      if (KEY(2) = '1') then
         next_state <= TEST_172; 
      elsif (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
		when TEST_172=>
      next_state <= TEST_172;
      if (KEY(6) = '1') then
         next_state <= TEST_1726; 
      elsif (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
		when TEST_1726=>
      next_state <= TEST_1726;
      if (KEY(3) = '1') then
         next_state <= TEST_17263; 
      elsif (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
   	when TEST_17263=>
      next_state <= TEST_17263;
      if (KEY(9) = '1') then
         next_state <= TEST_172639; 
      elsif (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
      when TEST_172639=>
      next_state <= TEST_172639;
      if (KEY(5) = '1') then
         next_state <= TEST_1726395; 
      elsif (KEY(6) = '1') then
         next_state <= TEST_1726396; 
      elsif (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
      when TEST_1726395=>
      next_state <= TEST_1726395;
      if (KEY(0) = '1') then
         next_state <= TEST_17263950; 
      elsif (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
      when TEST_17263950=>
      next_state <= TEST_17263950;
      if (KEY(4) = '1') then
         next_state <= TEST_172639504; 
      elsif (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
      when TEST_172639504=>
      next_state <= TEST_172639504;
      if (KEY(4) = '1') then
         next_state <= TEST_1726395044; 
      elsif (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
		when TEST_1726395044=>
      next_state <= TEST_1726395044;
      if (KEY(15) = '1') then
         next_state <= MESSAGE_OK; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
      when TEST_1726396=>
      next_state <= TEST_1726396;
      if (KEY(0) = '1') then
         next_state <= TEST_17263960; 
      elsif (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
      when TEST_17263960=>
      next_state <= TEST_17263960;
      if (KEY(3) = '1') then
         next_state <= TEST_172639603; 
      elsif (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
      when TEST_172639603=>
      next_state <= TEST_172639603;
      if (KEY(5) = '1') then
         next_state <= TEST_1726396035; 
      elsif (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
      when TEST_1726396035=>
      next_state <= TEST_1726396035;
      if (KEY(2) = '1') then
         next_state <= TEST_17263960352; 
      elsif (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
		when TEST_17263960352=>
      next_state <= TEST_17263960352;
      if (KEY(15) = '1') then
         next_state <= MESSAGE_OK; 
		elsif (KEY(14 downto 0) /= "000000000000000") then
			next_state <= TEST_ERROR;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
	when TEST_ERROR =>
      next_state <= TEST_ERROR;
      if (KEY(15) = '1') then
         next_state <= MESSAGE_ERR; 
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
	when MESSAGE_OK =>
      next_state <= MESSAGE_OK;
      if (CNT_OF = '1') then
         next_state <= FINISH;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
   when MESSAGE_ERR =>
      next_state <= MESSAGE_ERR;
      if (CNT_OF = '1') then
         next_state <= FINISH;
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
   when FINISH =>
      next_state <= FINISH;
      if (KEY(15) = '1') then
         next_state <= TEST_START; 
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
   when others =>
      next_state <= TEST_START;
   end case;
end process next_state_logic;

-- -------------------------------------------------------
output_logic : process(present_state, KEY)
begin
   FSM_CNT_CE     <= '0';
   FSM_MX_MEM     <= '0';
   FSM_MX_LCD     <= '0';
   FSM_LCD_WR     <= '0';
   FSM_LCD_CLR    <= '0';

   case (present_state) is
   -- - - - - - - - - - - - - - - - - - - - - - -
   when TEST_START | TEST_ERROR | TEST_1 | TEST_17 | TEST_172 | TEST_1726 | TEST_17263 | TEST_172639 | TEST_1726395 | TEST_17263950 | TEST_172639504 | TEST_1726395044 | TEST_1726396 | TEST_17263960 | TEST_172639603 | TEST_1726396035 | TEST_17263960352 =>
      if (KEY(14 downto 0) /= "000000000000000") then
         FSM_LCD_WR     <= '1';
      end if;
      if (KEY(15) = '1') then
         FSM_LCD_CLR    <= '1';
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
   when MESSAGE_ERR =>
      FSM_CNT_CE     <= '1';
      FSM_MX_LCD     <= '1';
      FSM_LCD_WR     <= '1';
   -- - - - - - - - - - - - - - - - - - - - - - -
	when MESSAGE_OK =>
      FSM_CNT_CE     <= '1';
      FSM_MX_LCD     <= '1';
      FSM_LCD_WR     <= '1';
		FSM_MX_MEM     <= '1';
   -- - - - - - - - - - - - - - - - - - - - - - -
   when FINISH =>
      if (KEY(15) = '1') then
         FSM_LCD_CLR    <= '1';
      end if;
   -- - - - - - - - - - - - - - - - - - - - - - -
   when others =>
   end case;
end process output_logic;

end architecture behavioral;

