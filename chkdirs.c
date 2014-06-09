/* Copyright (C) Hal Pomeranz <hal@deer-run.com> and Deer Run Assoc, 2002/11/24
   All rights reserved.  Permission granted to freely redistribute and update
   as long as this Copyright notice is preserved.  No warranty expressed or
   implied.

   $Id: chkdirs.c,v 1.3 2003/01/20 19:44:13 hal Exp $


   Usage:     chkdirs [-n] dir ...
   Examples:  chkdirs /
              chkdirs -n /proc
   Recursively traverses one or more directories looking for discrepancies
   between the parent directory link count and the number of subdirectories
   (parent directory link count should always equal the number of subdirs
   plus two-- anything else indicates a "hidden" directory).  "-n" option
   means check directory but don't recursively descend into subdirectories.

  Changelog :
  2002/12/19 - Little port for *BSB and Solaris - Nelson Murilo
  2003/01/09 - More fix for Solaris - Nelson Murilo
  2003/01/14 - HP-UX patch - Gerard Breiner
  2003/01/20 - NAME_MAX Fix by Hal Pomeranz
  2003/09/01 - BSDI port by Nelson Murilo and Thomas Davidson
  2005/22/05 - APPLE test for limits.h included by Aaron Harwood
  2007/08/10 - strncpy used instead of strcpy - nm
  2007/12/24 - change `c' variable type - NIDE, Naoyuki

*/

#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__sun) || defined (hpux) || defined (__bsdi__) || defined (bsdi) || defined (__APPLE__)
#include <limits.h>
#elif defined(__APPLE__) && defined(__MACH__)
#include <sys/syslimits.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>

#ifndef NAME_MAX
#define NAME_MAX        PATH_MAX
#endif

struct dirinfolist {
  char                   dil_name[NAME_MAX+1];
  int                    dil_lc;
  struct dirinfolist     *dil_next;
};


void usage ()
{
  fprintf(stderr, "chkdirs [-n] dir ...\n");
  exit(255);
}

char *make_pathname (char *path, char *dir, char **buffer)
{
  int plen, pathname_len, bufsize, offs;
  
  bufsize = 0; 

  plen = strlen(path);
  pathname_len = plen + strlen(dir) + 2;

  if (!(*buffer) || (sizeof(*buffer) < pathname_len)) {
    if (buffer) free((void *)*buffer);
    bufsize = (pathname_len > PATH_MAX) ? pathname_len : PATH_MAX;
    if (!(*buffer = (char *)malloc(bufsize))) {
      return((char *)NULL);
    }
  }

  if (dir[0] == '/') {   /* "dir" is absolute pathname, don't prepend "path" */
    offs = 0;
  }
  else {
    strncpy(*buffer, path, bufsize);
    if ((*buffer)[plen-1] == '/') {   /* "path" ends in "/", don't add extra */
      offs = plen;
    }
    else {
      (*buffer)[plen] = '/';
      offs = plen + 1;
    }
  }
  strncpy((*buffer)+offs, dir, bufsize - offs);
  return((*buffer));
}

int check_dir (char *dir, char *path, int linkcount, int norecurse)
{
  int diff = -1;
  int plen, buflen, numdirs;
  char *curpath, *fullpath;
  DIR *dirhandle;
  struct dirent *finfo;
  struct dirinfolist *dl, *dptr;
  struct stat statinfo;

  /* When called recursively, "path" will be the full path of the cwd,
     but when called from main() "path" is empty.  We need the cwd path
     so we can chdir() back at the end of this routine, as well as when
     printing errors and other output.
  */
  if (!path || !(plen = strlen(path))) {
    buflen = PATH_MAX;
  retry:
    if (!(curpath = (char *)malloc(buflen))) {
      fprintf(stderr, "malloc() failed: %s\n", strerror(errno));
      return(-1);
    }
    if (!getcwd(curpath, buflen)) {
      if (errno == ERANGE) {
	free((void *)curpath);
	buflen = buflen * 2;
	goto retry;
      }
      else {
	fprintf(stderr, "getcwd() failed: %s\n", strerror(errno));
	return(-1);
      }
    }
  }
  else {             /* "path" is set, so just copy it into "curpath" */
    if (!(curpath = (char *)malloc(plen+1))) {
      fprintf(stderr, "malloc() failed: %s\n", strerror(errno));
      return(-1);
    }
    strncpy(curpath, path, plen+1);
  }

  /* Now set "fullpath" to be the absolute path name of the directory
     we will be checking (prepend "curpath" if "dir" is not already an
     absolute pathname).
  */
  fullpath = (char *)NULL;
  if (!make_pathname(curpath, dir, &fullpath)) {
    fprintf(stderr, "make_pathname() failed: %s\n", strerror(errno));
    free((void *)curpath);
    return(-1);
  }

  if (chdir(dir)) {
    fprintf(stderr, "chdir(%s): %s\n", fullpath, strerror(errno));
    free((void *)curpath);
    free((void *)fullpath);
    return(-1);
  }

  /* Again, "linkcount" (the link count of the current directory) is set
     only if check_dir() is called recursively.  Otherwise, we need to
     stat the directory ourselves.
  */
  if (!linkcount) {
    if (lstat(".", &statinfo)) {
      fprintf(stderr, "lstat(%s): %s\n", fullpath, strerror(errno));
      goto abort;
    }
    linkcount = statinfo.st_nlink;
  }

  if (!(dirhandle = opendir("."))) {
    fprintf(stderr, "opendir(%s): %s\n", fullpath, strerror(errno));
    goto abort;
  }

  numdirs = 0;
  dl = (struct dirinfolist *)NULL;
  while ((finfo = readdir(dirhandle))) {
    if (!strcmp(finfo->d_name, ".") || !strcmp(finfo->d_name, ".."))
      continue;

    if (lstat(finfo->d_name, &statinfo)) {
      fprintf(stderr, "lstat(%s/%s): %s\n",
	      fullpath, finfo->d_name, strerror(errno));
      closedir(dirhandle);
      goto abort;
    }

    if (S_ISDIR(statinfo.st_mode)) {
      numdirs++;

      if (norecurse) continue;               /* just count subdirs if "-n" */

      /* Otherwise, keep a list of all directories found that have link
	 count > 2 (indicating directory contains subdirectories).  We'll
	 call check_dir() on each of these subdirectories in a moment...
      */
      if (statinfo.st_nlink > 2) {
	dptr = dl;
	if (!(dl = (struct dirinfolist *)malloc(sizeof(struct dirinfolist)))) {
	  fprintf(stderr, "malloc() failed: %s\n", strerror(errno));
	  norecurse = 1;
	  while (dptr) {
	    dl = dptr->dil_next;
	    free((void *)dptr);
	    dptr = dl;
	  }
	  continue;
	}

	strncpy(dl->dil_name, finfo->d_name, sizeof(dl->dil_name));
	dl->dil_lc = statinfo.st_nlink;
	dl->dil_next = dptr;
      }
    }
  }
  closedir(dirhandle);

  /* Parent directory link count had better equal #subdirs+2... */
  diff = linkcount - numdirs - 2;
  if (diff) printf("%d\t%s\n", diff, fullpath);

  /* Now check all subdirectories in turn... */
  while (dl) {
    check_dir(dl->dil_name, fullpath, dl->dil_lc, norecurse);
    dptr = dl->dil_next;
    free((void *)dl);
    dl = dptr;
  }

 abort:
  if (chdir(curpath)) {
    fprintf(stderr, "Final chdir(%s) failed (%s) -- EXIT!\n",
	    curpath, strerror(errno));
    exit(255);
  }
  free((void *)fullpath);
  free((void *)curpath);
  return(diff);
}


int main (int argc, char **argv)
{
  int norecurse = 0;
  int i, retval;
  int c;

  opterr = 0;
  while ((c = getopt(argc, argv, "n")) > 0) {
    switch (c) {
    case 'n':
      norecurse = 1;
      break;
    default:
      usage();
    }
  }
  if (argc <= optind) usage();

  for (i = optind; i < argc; i++) {
    retval = check_dir(argv[i], (char *)NULL, 0, norecurse);
  }
  exit(retval);
}
