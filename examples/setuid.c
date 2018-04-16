#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
  char buf[10];
  scanf("%s", buf);
  if(strcmp(buf, "crack") == 0)
  {
    setuid(0);
    setgid(0);
    printf("crack, uid=%d, gid=%d\n", getuid(), getgid());
    write(1, "hello world\n", 12);
  }
  else
  {
    setuid(0);
    printf("normal, uid=%d, gid=%d\n", getuid(), getgid());
  }
  setgid(0);

}