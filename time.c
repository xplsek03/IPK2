#include <sys/time.h>
#include <stdio.h>

int main() {
    
    struct timeval tv;
    
    gettimeofday(&tv,NULL);
    
    printf("%i\n",tv.tv_sec); // seconds
    printf("%i\n",tv.tv_usec); // microseconds

    return 0; 
}