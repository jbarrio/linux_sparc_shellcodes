    int main (int argc, char *argv[])
    {
      unsigned char ch;
      int a = 1;
      printf ("char sc[] = \n\"");
      while (1) {
        if (read (0, &ch, 1) != 1) break;
        printf ("\\x%02x", ch);
        if (!(a++ % 10)) printf ("\"\n\"");
      }
      printf ("\";\n");
    }
