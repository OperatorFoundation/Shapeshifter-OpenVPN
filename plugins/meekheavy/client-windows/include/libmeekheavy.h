//
// Created by z on 12/18/19.
//

#ifndef LIBMEEKHEAVY_LIBMEEKHEAVY_H
#define LIBMEEKHEAVY_LIBMEEKHEAVY_H
#include <stdint.h>
//global vars


//function prototypes
size_t curlWriteFunction(void *, size_t, size_t , void *);
void string2hexString(uint8_t *, char *, uint8_t );
int sessionIDgen(char *);

uint8_t initESNI(char *, char *, char *, char * );
uint8_t writeESNI(char *, size_t *);
uint32_t readESNI(char *,  size_t );
uint8_t closeESNI(void);


#endif //LIBMEEKHEAVY_LIBMEEKHEAVY_H
