/*
    Author:  Adrian Bobola, xbobol00@stud.fit.vutbr.cz
    Name:    Project n.2 for IZP 2019/2020 FIT VUT
    Date:    November 2019
 */

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>

#define I0 (1e-12)
#define Ut (25.8563e-3)

/* Funkcia vypocita pribliznu hodnotu parametra U0 pre zadane hodnoty
:param u0 = hodnota vstupniho napeti ve Voltech
:param r = odpor rezistoru v Ohmech
:param eps = absolutni chyba/prestnost/odchylka (epsilon)
:return: hodnota Up diody pre zadane vstupne parametre */
double diode(double u0, double r, double eps);

/*  Pomocna funkcia calculate_function_value() vrati funkcnu hodnotu funkcie
    :return: f(x) pre zadane vstupne parametre
 */
double calculate_function_value(double Up, double U0, double R) {
    double func, Ip, Ir, Ur;
    Ip = I0 * (exp(Up / Ut) - 1);
    Ur = U0 - Up;
    Ir = (Ur / R);
    func = Ip - Ir;

    return func;
}

/*
:param Argv[1] = U0 >= 0
:param Argv[2] = R > 0
:param Argv[3] = EPS > 0
:return: 0 pre uspesne ukoncenie programu
:return: 1 pre chybne hodnoty argumentov
 */
int main(int argc, char *argv[]) {
    double U0, R, EPS, Up, Ip;
    char *zvysok1, *zvysok2, *zvysok3 = NULL;

    if (argc != 4) {
        fprintf(stderr, "%s", "error: invalid arguments\n");
        return 4;
    }
    U0 = strtod(argv[1], &zvysok1);
    R = strtod(argv[2], &zvysok2);
    EPS = strtod(argv[3], &zvysok3);

    if ((R <= 0) || (EPS <= 0) || (U0 < 0) || (strlen(zvysok1) >= 1) || (strlen(zvysok2) >= 1) ||
        (strlen(zvysok3) >= 1)) {
        fprintf(stderr, "%s", "error: invalid arguments\n");
        return 1;
    }

    Up = diode(U0, R, EPS);
    Ip = I0 * (exp(Up / Ut) - 1);
    printf("Up=%g V\n", Up);
    printf("Ip=%g A\n", Ip);
    return 0;
}

double diode(double U0, double R, double eps) {
    double left_interval = 0;
    double right_interval = U0;
    double Up;
    double previous_Up_value;

    while (fabs(right_interval - left_interval) >= eps) {
        previous_Up_value = Up;
        Up = ((left_interval + right_interval) / 2);
        if ((calculate_function_value(Up, U0, R) == 0) || (previous_Up_value == Up)) {
            return Up;
        } else if ((calculate_function_value(Up, U0, R) * calculate_function_value(left_interval, U0, R)) < 0) {
            right_interval = Up;
        } else {
            left_interval = Up;
        }
    }
    return Up;
}
