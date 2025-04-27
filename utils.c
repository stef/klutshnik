#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sodium.h>

int debug = 0;
FILE* log_file=NULL;

void dump(const uint8_t *p, const size_t len, const char* msg, ...) {
  FILE* lf = stderr;
  if(!debug) return;
  if(log_file!=NULL) lf = log_file;
  va_list args;
  va_start(args, msg);
  vfprintf(lf, msg, args);
  va_end(args);
  fprintf(lf," ");
  for(size_t i=0;i<len;i++)
    fprintf(lf,"%02x", p[i]);
  fprintf(lf,"\n");
  fflush(lf);
}

void fail(const char* msg, ...) {
  va_list args;
  va_start(args, msg);
  fprintf(stderr, "\x1b[0;31m");
  vfprintf(stderr, msg, args);
  va_end(args);
  fprintf(stderr, "\x1b[0m\n");
}
