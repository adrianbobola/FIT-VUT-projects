library IEEE;
use IEEE.std_logic_1164.all;
use IEEE.std_logic_arith.all;
use IEEE.std_logic_unsigned.all;

-- rozhrani Vigenerovy sifry
entity vigenere is
   port(
         CLK : in std_logic;
         RST : in std_logic;
         DATA : in std_logic_vector(7 downto 0);
         KEY : in std_logic_vector(7 downto 0);

         CODE : out std_logic_vector(7 downto 0)
    );
end vigenere;

architecture behavioral of vigenere is
	signal posuv: std_logic_vector(7 downto 0); --8 bit
	signal plus_korekcia: std_logic_vector(7 downto 0);
	signal minus_korekcia: std_logic_vector(7 downto 0);
	type tState is (pridat, odobrat);
	signal stav: tState := pridat;
	signal dalsi_stav: tState := odobrat;
	signal fsm_output: std_logic_vector(1 downto 0); --2 bit
	signal hashtag: std_logic_vector(7 downto 0);

begin
	-----------------------------------------------------------------------------------
	-- Korekcia posuvu

	-- vypocet velkosti posuvu
	vypocet_velikosti_posuvu: process (KEY, DATA, posuv) is
	begin 
		posuv <= (KEY - 64);
	end process;

	-- korekcia plus - Vypocitam hodnotu pre plus, ak je to mimo rozsah A-Z - upravim hodnotu pre potrebny rozsah
	Plus_s_korekci: process (DATA, posuv) is
		variable helper: std_logic_vector(7 downto 0);
	begin
		helper := (DATA + posuv);
		if(helper > 90) then --kontrola prekrocenia za pismeno Z
			helper := (helper - 26);
		end if;
		plus_korekcia <= helper;
	end process;

	-- korekcia minus - Vypocitam hodnotu pre operaciu minus, ak je mimo A-Z - upravi sa hodnota pre potrebny rozsah
	Minus_s_korekci: process (DATA, posuv) is
		variable helper: std_logic_vector(7 downto 0);
	begin
		helper := (DATA - posuv);
		if(helper < 65) then --kontrola prekrocenia pod pismeno A
			helper := (helper + 26);
		end if;
		minus_korekcia <= helper;
	end process;
	-------------------------------------------------------------------------------------
	-- Mealyho automat
	Stav_logika: process (CLK, RST, stav) is
	begin
		if (RST = '1') then --signal reset = 1, nastane stav pridat
			stav <= pridat;
		elsif (CLK'event) and (CLK = '1') then --signal clock = 1, prechadzam na dalsi stav
			stav <= dalsi_stav;
		end if;
	end process;
	
	-- FSM_Mealy
	FSM_Mealy: process (DATA, RST, stav) is
	begin
	  	--- riesim aky bude dalsi stav ---
		if (stav = odobrat) then --som v stave odobrat, preto nasleduje pridat, nastavim fsm hodnotu pre multiplexor
			dalsi_stav <= pridat;
			fsm_output <= "10";
		end if;
	
		if (stav = pridat) then --som v stave pridat, preto nasleduje stav odobrat, nastavim fsm hodnotu pre multiplexor
			dalsi_stav <= odobrat;
			fsm_output <= "01";
		end if;

		if (((DATA < 58) and (DATA > 47)) or (RST = '1')) then --DATA obsahuje cisla 0-9 alebo nastal reset, nastavim fsm hodnotu pre multiplexor
			fsm_output <= "00";
		end if;
	end process;
	------------------------------------------------------------------------------------
	-- multiplexor
	Multiplexor: process (plus_korekcia, minus_korekcia, hashtag, fsm_output) is
	begin
		hashtag <= "00100011";
		if (fsm_output = "10") then --Mpx dostal od FSM signal 10, ktory sme vo FSM definovali pre stav odobrat, preto sa aplikuje operacia minus
			CODE <= minus_korekcia;
		elsif (fsm_output = "01") then --Mpx dostal od FSM signal 01, ktory sme vo FSM definovali pre stav pridat, aplikuje sa operacia plus
			CODE <= plus_korekcia;
		else --DATA obsahuju 0-9 alebo nastal reset, aplikuje sa pridanie #
			CODE <= hashtag;
		end if;
	end process;
end behavioral;
 
