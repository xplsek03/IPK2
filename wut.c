#include <stdio.h>
#include <stdlib.h>


struct test{
    int a;
    int b;
};

void proof(struct test *t) {
    for(int i = 0; i < 20; i++) {
        t[i].a = 5;
    }
}

// dukaz ze se struktura da zmenit z extenri funkce takhle.
int main (int argc, const char * argv[])
{
    printf("dsdsd.");
    struct test *t = malloc(sizeof(struct test) * 20);

    proof(t);

    for(int i = 0; i < 20; i++) {
        printf("%i\n",t[i].a);
    }

    return 0;
}