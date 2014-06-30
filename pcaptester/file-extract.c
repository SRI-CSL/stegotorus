#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include "winnt.h"

#define BUFSIZE 1000

#define TYPE_PDF 1
#define TYPE_JS 2
#define TYPE_HTML 3
#define TYPE_SWF 4

int type = 0;



int main (int argc, char** argv) {
  FILE* input = fopen(argv[1], "r");
  FILE* output = fopen("tmp.out", "w");
  char line[BUFSIZE];
  char* pos;
  bzero(line, BUFSIZE);

  int size = 0;
  int min_len = 0;
  int bytes_so_far = 0;
  int gzipped = 0;


  while(fgets(line, BUFSIZE, input) != 0) {
    if (strstr(line, "Content-Length") != NULL) {
      char* tok = strtok(line, " ");
      tok = strtok(NULL, " \r\n");
      min_len = strtoul(tok, NULL, 10);            
    }

    if (strstr(line, "Content-Encoding") != NULL && strstr(line, "gzip") != NULL)
      gzipped =1;

    if (strstr(line, "Content-Type:") != NULL) {
      if (strstr(line, "shockwave") != NULL) {
	type = TYPE_SWF;
      }
      else if (strstr(line, "javascript") != NULL) {
	type = TYPE_JS;
      }
      else if (strstr(line, "html") != NULL) {
	type = TYPE_HTML;
      }
      else if (strstr(line, "pdf") != NULL) {
	type = TYPE_PDF;
      }
    }

    if (strcmp(line, "\r\n") == 0)
      break;
  }

  
  while ((size = fread(line, 1, BUFSIZE, input)) != 0) {
    if (bytes_so_far + size < min_len) {
      fwrite(line, 1, size, output);
      bytes_so_far += size;
    }
    else {
      fwrite(line, 1, min_len-bytes_so_far, output);
      bytes_so_far += size;
      fclose(output);
      fclose(input);
      break;
    }
  }


  if (bytes_so_far < min_len)
    fprintf(stderr, "truncated file? %d %d\n", bytes_so_far, min_len);

  if (gzipped) {
    system("mv tmp.out tmp.out.gz");
    system("gunzip tmp.out.gz");    
    
  } 
  sprintf(line, "mv tmp.out %s", argv[2]);
  system(line);


}
