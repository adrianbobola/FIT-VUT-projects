proc isim_script {} {

   add_divider "Signals of the Vigenere Interface"
   add_wave_label "" "CLK" /testbench/clk
   add_wave_label "" "RST" /testbench/rst
   add_wave_label "-radix ascii" "DATA" /testbench/tb_data
   add_wave_label "-radix ascii" "KEY" /testbench/tb_key
   add_wave_label "-radix ascii" "CODE" /testbench/tb_code

   add_divider "Vigenere Inner Signals"
   # sem doplnte vase vnitrni signaly. chcete-li v diagramu zobrazit desitkove
   # cislo, vlozte do prvnich uvozovek: -radix dec
   add_wave_label "-radix ascii" "PLUS" /testbench/uut/plus_korekcia
   add_wave_label "-radix ascii" "MINUS" /testbench/uut/minus_korekcia
   add_wave_label "-radix unsigned" "POSUV" /testbench/uut/posuv
   add_wave_label "" "STAV" /testbench/uut/stav
   add_wave_label "" "STAV_DALSI" /testbench/uut/dalsi_stav
   add_wave_label "" "FSM_OUTPUT" /testbench/uut/fsm_output

   run 8 ns
}
