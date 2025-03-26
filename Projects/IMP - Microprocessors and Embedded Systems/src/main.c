/**
 * FIT VUT - IMP projekt
 * ESP32 - Pristupovy terminal
 * 
 * @author Adrian Bobola - xbobol00
 */

#include <freertos/FreeRTOS.h>
#include "driver/gpio.h"
#include "esp_event.h"

// GPIO porty
#define COL1 23
#define COL2 18
#define COL3 13
#define ROW1 19
#define ROW2 14
#define ROW3 12
#define ROW4 27
#define LED_GREEN 16
#define LED_RED 17

bool col1_is_set = false;
bool col2_is_set = false;
bool col3_is_set = false;
char right_code[4] = {'1', '2', '3', '4'};
char input_code[10] = {'0', '0', '0', '0', '0', '0', '0', '0', '0', '0'};
int array_index = 0;
int code_length = 4;

/**
 * @brief Pociatocna inicializacia GPIO vstupov a vystupov
 * 
 */
void configure_GPIO(void)
{
  // GPIO SET COL 1-3
  gpio_pad_select_gpio(COL1);
  gpio_set_direction(COL1, GPIO_MODE_OUTPUT);
  gpio_pad_select_gpio(COL2);
  gpio_set_direction(COL2, GPIO_MODE_OUTPUT);
  gpio_pad_select_gpio(COL3);
  gpio_set_direction(COL3, GPIO_MODE_OUTPUT);

  // GPIO SET ROW 1-4
  gpio_reset_pin(ROW1);
  gpio_set_direction(ROW1, GPIO_MODE_INPUT);
  gpio_set_pull_mode(ROW1, GPIO_PULLDOWN_ONLY);
  gpio_reset_pin(ROW2);
  gpio_set_direction(ROW2, GPIO_MODE_INPUT);
  gpio_set_pull_mode(ROW2, GPIO_PULLDOWN_ONLY);
  gpio_reset_pin(ROW3);
  gpio_set_direction(ROW3, GPIO_MODE_INPUT);
  gpio_set_pull_mode(ROW3, GPIO_PULLDOWN_ONLY);
  gpio_reset_pin(ROW4);
  gpio_set_direction(ROW4, GPIO_MODE_INPUT);
  gpio_set_pull_mode(ROW4, GPIO_PULLDOWN_ONLY);

  // GPIO SET LED
  gpio_pad_select_gpio(LED_GREEN);
  gpio_set_direction(LED_GREEN, GPIO_MODE_OUTPUT);
  gpio_pad_select_gpio(LED_RED);
  gpio_set_direction(LED_RED, GPIO_MODE_OUTPUT);
  gpio_set_level(LED_RED, 1);
  gpio_set_level(LED_GREEN, 0);
}

/**
 * @brief Blikanie cervenej LED diody
 * 
 */
void red_LED_blink()
{
  for (int i = 0; i < 4; i++)
  {
    gpio_set_level(LED_RED, 1);
    vTaskDelay(100 / portTICK_RATE_MS);
    gpio_set_level(LED_RED, 0);
    vTaskDelay(100 / portTICK_RATE_MS);
  }
  gpio_set_level(LED_RED, 1);
}

/**
 * @brief Blikanie zelenej LED diody
 * 
 */
void green_LED_blink()
{
  gpio_set_level(LED_RED, 0);
  for (int i = 0; i < 5; i++)
  {
    gpio_set_level(LED_GREEN, 1);
    vTaskDelay(100 / portTICK_RATE_MS);
    gpio_set_level(LED_GREEN, 0);
    vTaskDelay(100 / portTICK_RATE_MS);
  }
  gpio_set_level(LED_RED, 1);
}

/**
 * @brief Zapni zelenu LED diodu ma 1 sekundu
 * 
 */
void turn_on_green_LED()
{
  gpio_set_level(LED_RED, 0);
  gpio_set_level(LED_GREEN, 1);
  vTaskDelay(1000 / portTICK_RATE_MS);
  gpio_set_level(LED_GREEN, 0);
  gpio_set_level(LED_RED, 1);
}

/**
 * @brief Aktivacia pozadovaneho stlpca, ostatne vypne
 * 
 * @param colnb - cislo stlpca ktory chceme aktivovat (1-3)
 */
static void set_col(int colnb)
{
  if (colnb == 1)
  {
    col1_is_set = true;
    col2_is_set = false;
    col3_is_set = false;
    gpio_set_level(COL1, 1);
    gpio_set_level(COL2, 0);
    gpio_set_level(COL3, 0);
  }
  else if (colnb == 2)
  {
    col1_is_set = false;
    col2_is_set = true;
    col3_is_set = false;
    gpio_set_level(COL1, 0);
    gpio_set_level(COL2, 1);
    gpio_set_level(COL3, 0);
  }
  else if (colnb == 3)
  {
    col1_is_set = false;
    col2_is_set = false;
    col3_is_set = true;
    gpio_set_level(COL1, 0);
    gpio_set_level(COL2, 0);
    gpio_set_level(COL3, 1);
  }
}

/**
 * @brief Cakanie na stlacenie tlacidla klavesnice
 * 
 * @return char - stlaceny symbol na klavesnici
 */
char waiting_for_button(void)
{
  while (1)
  {
    // enabling first COL and checking ROW 1-4
    set_col(1);
    if (col1_is_set)
    {
      if (gpio_get_level(ROW1) == 1)
      {
        return ('1');
      }
      else if (gpio_get_level(ROW2) == 1)
      {
        return ('4');
      }
      else if (gpio_get_level(ROW3) == 1)
      {
        return ('7');
      }
      else if (gpio_get_level(ROW4) == 1)
      {
        return ('*');
      }
    }

    // enabling second COL and checking ROW 1-4
    set_col(2);
    if (col2_is_set)
    {
      if (gpio_get_level(ROW1) == 1)
      {
        return ('2');
      }
      else if (gpio_get_level(ROW2) == 1)
      {
        return ('5');
      }
      else if (gpio_get_level(ROW3) == 1)
      {
        return ('8');
      }
      else if (gpio_get_level(ROW4) == 1)
      {
        return ('0');
      }
    }

    // enabling third COL and checking ROW 1-4
    set_col(3);
    if (col3_is_set)
    {
      if (gpio_get_level(ROW1) == 1)
      {
        return ('3');
      }
      else if (gpio_get_level(ROW2) == 1)
      {
        return ('6');
      }
      else if (gpio_get_level(ROW3) == 1)
      {
        return ('9');
      }
      else if (gpio_get_level(ROW4) == 1)
      {
        return ('#');
      }
    }
  }
}

/**
 * @brief resetuj doteraz zadane symboly
 * 
 */
void reset_input_key()
{
  for (int i = 0; i < 10; i++)
  {
    input_code[i] = '0';
  }
  array_index = 0;
  code_length = 4;
  printf("---------------- RESET VSTUPU -----------\n");
}

/**
 * @brief Vypis doterz zadane symboly kodu do terminalu
 * 
 */
void print_input_key()
{
  printf("ZADAVANY KOD: ");
  for (int i = 0; i < code_length; i++)
  {
    printf("%c ", input_code[i]);
  }
  printf("\n");
}

/**
 * @brief Skontroluj a ak je kod spravny, zmen ho za novy
 * 
 */
void check_and_change_code()
{
  for (int i = 0; i < 4; i++)
  {
    if (input_code[i + 1] != right_code[i])
    {
      printf("ZADANY KOD SA NEZHODUJE! Zostava nezmeneny\n");
      red_LED_blink();
      reset_input_key();
      break;
    }
    // Kod sa zhoduje - chceme ho zmenit
    if (i == 3)
    {
      printf("NOVY KOD NASTAVENY\n");
      green_LED_blink();
      for (int i = 6; i < 10; i++)
      {
        right_code[i - 6] = input_code[i];
      }
      reset_input_key();
    }
  }
}

/**
 * @brief Skontroluj zadany kod
 * 
 */
void check_code()
{
  for (int i = 0; i < 4; i++)
  {
    if (input_code[i] != right_code[i])
    {
      printf("KOD NESPRAVNY!\n");
      red_LED_blink();
      reset_input_key();
      break;
    }
    if (i == 3)
    {
      printf("KOD OK\n");
      turn_on_green_LED();
      reset_input_key();
    }
  }
}

void app_main(void)
{
  configure_GPIO();
  while (1)
  {
    // Cakam na vstup klavesnice
    char returnvalue = waiting_for_button();
    input_code[array_index] = returnvalue;
    array_index++;
    print_input_key();

    // Stlacene tlacidlo # a hned prve - input bude 10 znakovy
    if ((returnvalue == '#') && (array_index == 1))
      code_length = 10;

    // Nacital som 4 znaky a nebude sa menit kod
    if ((code_length == 4) && (array_index == 4))
      check_code();

    // Nacital som uz 10 znakov a bude sa kod menit
    else if ((code_length == 10) && (array_index == 10))
      check_and_change_code();

    vTaskDelay(200 / portTICK_RATE_MS);
  }
}
