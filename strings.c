/*
 * Poor developer's strings.
 * (c) 2002, Sean D. True, WebReply.Com, Inc.
 * Use freely, under the Python license
 * In short: use with or without attribution as you like, but
 * no warranty of fitness, suitability, or anything else is given!
 *
 * ChangeLog:
 * superfluous printable() function deleted - 2002/02/20 - Nelson Murilo
 */

#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdlib.h>
#ifdef __FreeBSD__ 
#include <string.h> 
#endif
#ifdef __linux__ 
#include <string.h> 
#endif

#define MAXFILESIZE (4*1024*1024)

/*
 * Many options here. The current choice produces a little more output
 * than gnu strings
 */

/*
 * Try to get the filesize via stat, and get a buffer to match
 * Naievely allocate a 4MB buffer if we can't
 * Fails badly if it allocate a buffer big enough to load a file
 */
unsigned char *filebuf(FILE *pf, int *sz) {
  struct stat buf;
  unsigned char *cdata;

  if (fstat(fileno(pf), &buf) < 0) {
    perror("fstat");
    exit (1);
  }

  *sz = buf.st_size;
  if(*sz == 0) *sz = MAXFILESIZE;

  if ((cdata = malloc(*sz+1)) == NULL) {
    perror("malloc");
    exit (1);
  }
  return cdata;
}

/*
 * Find printable strings of 4 or more characters
 * Always scans entire file (-a option of gnu strings)
 */
void strings(FILE *pf) {
  static char printme[1024];
  int sz;
  unsigned char *cdata;
  int nread;
  int printmeindex;
  cdata = filebuf(pf,&sz);
  nread = fread(cdata, 1, sz, pf);
  printmeindex = 0;
  if (nread > 0) {
    int i;
    unsigned char c;
    int isprintable;
    int iseol;
    for (i = 0; i < nread; i++) {
      c = cdata[i];
      isprintable = isprint(c);
      iseol = 0;
      if (c == 0 || c == '\n' || printmeindex >= sizeof(printme)-1) iseol = 1;
      if (iseol || !isprintable) {
	if (printmeindex > 3 && iseol) {
	  printme[printmeindex++] = 0;
	  printf("%s\n", printme);
	  printmeindex = 0;
	}
      }
      else if (isprintable) {
	printme[printmeindex++] = c;
      }
    }
  }
  if (printmeindex > 3) {
    printme[printmeindex++] = 0;
    printf("%s\n", printme);
    printmeindex = 0;
  }
  free(cdata);
}

/*
 * Silently accepts the -a option
 */
int main(int argc, char **argv)
{
  if (argc > 1) {
    int i;
    for (i = 1; i < argc; i++) {
      FILE *pf;
      if (strcmp(argv[i], "-a") == 0) continue;

      if ((pf = fopen(argv[i],"rb")) == NULL) {
        perror("fopen");
        return(1);
      }
      strings(pf);
    }
  }
  else {
    strings(stdin);
  }
  return(0);
}
