#include <stdio.h>

int main() {
  long int i = 15;
  const char *p = (const char *) &i;
  if (p[0] == 5) {
    printf ("Little Endian\n");
  } else {
      printf ("Big Endian\n");
    }
  return (0);
}
