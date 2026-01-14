#include <stdio.h>
void marker() { puts("marker"); }
int main() { puts("start"); marker(); puts("end"); return 0; }