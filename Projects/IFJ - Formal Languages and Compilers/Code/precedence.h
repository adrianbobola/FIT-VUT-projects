#ifndef IFJ20C_PRECEDENCE_H
#define IFJ20C_PRECEDENCE_H

#include "token.h"

typedef enum{
    PRECEDENCE_X, //!' ' Rule not allowed
    PRECEDENCE_L, //! <  SHIFT
    PRECEDENCE_G, //! >  Reduce
    PRECEDENCE_E  //! =  Equal
} Precedence_sign;

// This makes the table prettier. Beauty is also subjective.
// I want my enum structs :/
#define X PRECEDENCE_X
#define L PRECEDENCE_L
#define G PRECEDENCE_G
#define E PRECEDENCE_E
Precedence_sign precedence_table[7][7] = {
        //|      | +,- | *,/ | ( | ) | i | r | $ |
        //|:----:|:---:|:---:|:-:|:-:|:-:|:-:|:-:|
        /*| +,- */{ G  ,  L  , L , G , L , G , G },
        /*| *,/ */{ G  ,  G  , L , G , L , G , G },
        /*|  (  */{ L  ,  L  , L , E , L , L , X },
        /*|  )  */{ G  ,  G  , X , G , X , G , G },
        /*|  i  */{ G  ,  G  , X , G , X , G , G },
        /*|  r  */{ L  ,  L  , L , G , L , X , G },
        /*|  $  */{ L  ,  L  , L , X , L , L , X },
};
#undef X
#undef L
#undef G
#undef E

Precedence_sign precedence_lookup(Token_type top, Token_type input_token);

#endif //IFJ20C_PRECEDENCE_H
