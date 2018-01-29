/*
  (C) Nelson Murilo - 2004/09/13
  Version 0.10
  C port from chkproc.pl code from Klaus Steding-Jessen <jessen@nic.br>
  and Cristine Hoepers <cristine@nic.br> +little output changes.

  2002/03/02 - Segmentation fault in ps for non ASCII user name, by RainbowHat

  2002/06/13 Updated by Kostya Kortchinsky <kostya.kortchinsky@renater.fr>
  - corrected the program return value ;
  - added a verbose mode displaying information about the hidden process.

  2002/08/08 - Value of MAX_PROCESSES was increased to 99999 (new versions
    of FreeBSD, HP-UX and others), reported by Morohoshi Akihiko, Paul
    and others.

  2002/09/03 - Eliminate (?) false-positives. Original idea from Aaron Sherman.

  2002/11/15 - Updated by Kostya Kortchinsky <kostya.kortchinsky@renater.fr>
  - ported to SunOS.

  2003/01/19 - Another Adore based lkm test. Original idea from Junichi Murakami

  2003/02/02 - More little fixes - Nelson Murilo

  2003/02/23 - Use of kill to eliminate false-positives abandonated, It is
  preferable false-positives that false-negatives. Uncomment kill() functions
  if you like  it.

  2003/06/07 - Fix for NPTL threading mechanisms - patch by Mike Griego

  2003/09/01 - Fix for ps mode detect, patch by Bill Dupree and others

  2004/04/03 - More fix for linux's threads - Nelson Murilo

  2004/09/13 - More and more fix for linux's threads - Nelson Murilo

  2005/02/23 - More and more and more fix for linux's threads - Nelson Murilo

  2005/10/28 - Bug fix for FreeBSD: chkproc was sending a SIGXFSZ (kill -25)
               to init, causing a reboot.  Patch by Nelson Murilo.
               Thanks to Luiz E. R. Cordeiro.

  2005/11/15 - Add check for Enye LKM - Nelson Murilo

  2005/11/25 - Fix for long lines in PS output - patch by Lantz Moore

  2006/01/05 - Add getpriority to identify LKMs, ideas from Yjesus(unhide) and
               Slider/Flimbo (skdet)

  2006/01/11 - Fix signal 25 on parisc linux and return of kill() -
               Thanks to Lantz Moore

  2014/07/16 -  MAX_PROCESSES now is 999999 - 
		Thanks to Nico Koenrades
*/

#if !defined(__linux__) && !defined(__FreeBSD__) && !defined(__sun)
int main (){ return 0; }
#else
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#if defined(__sun)
#include <procfs.h>
#include <fcntl.h>
#endif
#include <sys/resource.h>

#define PS_SUN 0
#define PS_LOL 1
#define PS_COM 2
#define PS_LNX 3
#define PS_MAX 3
#define ENYELKM "/proc/12345"
// #define ENYELKM "/tmp/12345"

#if defined(__sun)
#define FIRST_PROCESS 0
#else
#define FIRST_PROCESS 1
#endif
#define MAX_PROCESSES 999999 
#define MAX_BUF 1024

#if !defined (SIGXFSZ)
#define SIGXFSZ 25
#endif

static char *ps_cmds[] = {
	    "ps -edf",
	    "ps auxw",
	    "ps mauxw 2>&1 ",
            "ps auxw -T|tr -s ' '|cut -d' ' -f2-",
          };

int psproc [MAX_PROCESSES+1];
int dirproc[MAX_PROCESSES+1];
#if defined(__linux__)
int isathread[MAX_PROCESSES+1];
#endif

/*
 * read at most the first (size-1) chars into s and terminate with a '\0'.
 * stops reading after a newline or EOF.  if a newline is read, it will be
 * the last char in the string.  if no newline is found in the first
 * (size-1) chars, then keep reading and discarding chars until a newline
 * is found or EOF.
 */
char *readline(char *s, int size, FILE *stream)
{
  char *rv = fgets(s, size, stream);

  if (strlen(s) == (size-1) && s[size-1] != '\n')
  {
    char buf[MAX_BUF];
    fgets(buf, MAX_BUF, stream);
    while (strlen(buf) == (MAX_BUF-1) && buf[MAX_BUF-1] != '\n')
    {
      fgets(buf, MAX_BUF, stream);
    }
  }

  return rv;
}

int main(int argc, char **argv)
{
   char buf[MAX_BUF], *p, path[MAX_BUF];
   char *pscmd = (char *)0;
   FILE *ps;
   DIR *proc = opendir("/proc");
   struct dirent *dir;
   struct stat sb;
   int i, j, retps, retdir, pv, verbose;
   long ret = 0L;
   char * tmp_d_name;
#if defined(__linux__)
   int maybeathread;
#endif
#if defined(__sun)
   psinfo_t psbuf;
#endif

   pv = verbose = 0;

   if (!proc)
   {
      perror("proc");
      exit (1);
   }
   for (i = 1; i < argc; i++)
   {
      if (!memcmp(argv[i], "-v", 2))
	verbose++;
      else if (!memcmp(argv[i], "-?", 2))
      {
	printf("Usage: %s [-v] [-v] -p <num>\n", argv[0]);
	return 0;
      }
#if defined(__linux__)
      else if (!memcmp(argv[i], "-p", 2))
      {
         if (i+1 < argc)
            pv = atoi(argv[++i]);
         else
         {
	    printf("Usage: %s [-v] [-v] [-p procps version]\n", argv[0]);
	    return 0;
         }
      }
#endif
   }
#if defined(__sun)
   pscmd = ps_cmds[PS_SUN];
#elif !defined (__linux__)
   pscmd = ps_cmds[PS_COM];
#endif
#if defined(__linux__)
   if (pv < 1 || pv > PS_MAX)
      pv = 1;
   pscmd = ps_cmds[pv];
/*  printf("pv = %d\n\r", pv); /* -- DEBUG */
#endif

/* printf("pscmd = %s\n\r", pscmd); /* -- DEBUG */
   if (!(ps = popen(pscmd, "r")))
   {
       perror("ps");
       exit(errno);
   }

   *buf = 0;
   readline(buf, MAX_BUF, ps); /* Skip header */
#if defined(__sun)
   if (!isspace(*buf))
#else
   if (!isalpha(*buf))
#endif
   {
     readline(buf, MAX_BUF, ps); /* Skip header */
     if (!isalpha(*buf) && pv != PS_LNX)
     {
	if (pv != PS_LOL)
	   execlp(argv[0], argv[0], "-p 1", NULL);
        fprintf(stderr, "OooPS!\n");
        exit(2);
     }
   }
   if (!memcmp(buf, "ps:", 3) && (pv != PS_LOL))
      execlp(argv[0], argv[0], "-p 1", NULL);

   for (i = FIRST_PROCESS; i <= MAX_PROCESSES; i++) { /* Init matrix */
     psproc[i] = dirproc[i] = 0;
#if defined(__linux__)
     isathread[i] = 0;
#endif
   }

   while (readline(buf, MAX_BUF, ps))
   {
      p = buf;
#if defined(__sun)
      while (isspace(*p)) /* Skip spaces */
          p++;
#endif
      while (!isspace(*p)) /* Skip User */
          p++;
      while (isspace(*p)) /* Skip spaces */
          p++;
/*  printf(">>%s<<\n", p);  /* -- DEBUG */
      ret = atol(p);
      if ( ret < 0 || ret > MAX_PROCESSES )
      {
         fprintf (stderr, " OooPS, not expected %ld value\n", ret);
         exit (2);
      }
      psproc[ret] = 1;
   }
   pclose(ps);

   while ((dir = readdir(proc)))
   {
#if defined(__linux__)
      maybeathread = 0;
#endif
      tmp_d_name = dir->d_name;
      if (!strcmp(tmp_d_name, ".") || !strcmp(tmp_d_name, ".."))
         continue;
#if defined(__linux__)
      if (*tmp_d_name == '.') { /* here we catch the new NTPL threads in linux.  They are listed in /proc as PIDs with a period prepended */
         tmp_d_name++;
         maybeathread = 1;
      }
#endif
      if(!isdigit(*tmp_d_name))
         continue;
#if defined(__linux__)
      else if (maybeathread) {
         isathread[atol(tmp_d_name)] = 1; /* mark it as a linux NTPL thread if it's in the form of "\.[0-9]*" */
         if (verbose)
            printf("%ld is a Linux Thread, marking as such...\n", atol(tmp_d_name));
      }
#endif

/*      printf("%s\n", tmp_d_name); /* -- DEBUG */
      dirproc[atol(tmp_d_name)] = 1;
   }
   closedir(proc);

   /* Brute force */
   strcpy(buf, "/proc/");
   retps = retdir = 0;
   for (i = FIRST_PROCESS; i <= MAX_PROCESSES; i++)
   {
      // snprintf(&buf[6], 6, "%d", i);
       snprintf(&buf[6], 8, "%d", i);
      if (!chdir(buf))
      {
         if (!dirproc[i] && !psproc[i])
         {
#if defined(__linux__)
            if (!isathread[i]) {
#endif
            retdir++;
            if (verbose)
	       printf ("PID %5d(%s): not in readdir output\n", i, buf);
#if defined(__linux__)
            }
#endif
         }
         if (!psproc[i] ) /* && !kill(i, 0)) */
         {
#if defined(__linux__)
            if(!isathread[i]) {
#endif
            retps++;
            if (verbose)
	       printf ("PID %5d: not in ps output\n", i);
#if defined(__linux__)
            }
#endif
	 }
#if defined(__linux__)
         if(!isathread[i]) {
#endif
/*	 if ((!dirproc[i] || !psproc[i]) && !kill(i, 0) && (verbose > 1)) */
	 if ((!dirproc[i] || !psproc[i]) && (verbose > 1))
	 {
#if defined(__linux__)
	    j = readlink ("./cwd", path, sizeof(path));
	    path[(j < sizeof(path)) ? j : sizeof(path) - 1] = 0;
	    printf ("CWD %5d: %s\n", i, path);
	    j = readlink ("./exe", path, sizeof(path));
	    path[(j < sizeof(path)) ? j : sizeof(path) - 1] = 0;
	    printf ("EXE %5d: %s\n", i, path);
#elif defined(__FreeBSD__)
	    j = readlink ("./file", path, sizeof(path));
	    path[(j < sizeof(path)) ? j : sizeof(path) - 1] = 0;
	    printf ("FILE %5d: %s\n", i, path);
#elif defined(__sun)
	    if ((j = open("./psinfo", O_RDONLY)) != -1)
            {
               if (read(j, &psbuf, sizeof(psbuf)) == sizeof(psbuf))
                  printf ("PSINFO %5d: %s\n", i, psbuf.pr_psargs);
               else
                  printf ("PSINFO %5d: unknown\n", i);
               close(j);
            }
            else
               printf ("PSINFO %5d: unknown\n", i);
#endif
         }
#if defined(__linux__)
         }
#endif
      }
#ifndef __FreeBSD__
      else
      {
         errno = 0;
         getpriority(PRIO_PROCESS, i);
         if (!errno)
         {
            retdir++;
            if (verbose)
	       printf ("PID %5d(%s): not in getpriority readdir output\n", i, buf);
	 }
      }
#endif
   }
   if (retdir)
      printf("You have % 5d process hidden for readdir command\n", retdir);
   if (retps)
      printf("You have % 5d process hidden for ps command\n", retps);
#if defined(__linux__)
   kill(1, 100); /*  Check for SIGINVISIBLE Adore signal */
   if (kill (1, SIGXFSZ) < 0  && errno == 3)
   {
      printf("SIGINVISIBLE Adore found\n");
      retdir+= errno;
   }
   /* Check for Enye LKM */
   if (stat(ENYELKM, &sb) && kill (12345, 58) >= 0)
   {
      printf("Enye LKM found\n");
      retdir+= errno;
   }
#endif
   return (retdir+retps);
}
#endif
