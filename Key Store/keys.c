#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char *get_key(int node) {
  char command[100];
  FILE *fp;
  char path[1035];
  strcpy(command, "python get_key.py ");
  char str[4];
  snprintf(str, 4, "%d", node);
  strcat(command, str);
  fp = popen(command, "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
  }
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
  }
   pclose(fp);
   return path;
}


void *put_key(int node,char *key) {
  char command[1000];
  FILE *fp;
  char path[1035];
  strcpy(command, "python put_key.py ");
  char str[4];
  snprintf(str, 4, "%d", node);
  strcat(command, str);
  strcat(command, " ");
  strcat(command, key);
  fp = popen(command, "r");
  if (fp == NULL) {
    printf("Failed to run command\n" );
    exit(1);
  }
  while (fgets(path, sizeof(path)-1, fp) != NULL) {
  }
   pclose(fp);
}




int main(int argc, char *argv[] )
{
  char * string="asdasdasdasdad";
  put_key(5,string);
  char *string_1;
  string_1=get_key(5);
  printf("%s",string_1);
	return 0;
}
