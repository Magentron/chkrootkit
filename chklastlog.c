/*
   Copyright (c) DFN-CERT, Univ. of Hamburg 1994

   Univ. Hamburg, Dept. of Computer Science
   DFN-CERT
   Vogt-Koelln-Strasse 30
   22527 Hamburg
   Germany

   02/20/97 - Minimal changes for Linux/FreeBSD port.
   02/25/97 - Another little bit change
   12/26/98 - New Red Hat compatibility
   Nelson Murilo, nelson@pangeia.com.br
   01/05/00 - Performance patches
   09/07/00 - Ports for Solaris
   Andre Gustavo de Carvalho Albuquerque
   12/15/00 - Add -f & -l options
   Nelson Murilo, nelson@pangeia.com.br
   01/09/01 - Many fixes
   Nelson Murilo, nelson@pangeia.com.br
   01/20/01 - More little fixes
   Nelson Murilo, nelson@pangeia.com.br
   24/01/01 - Segfault in some systems fixed, Thanks to Manfred Bartz
   02/06/01 - Beter system detection & fix bug in OBSD, Thanks to Rudolf Leitgeb
   09/19/01 - Another Segfault in some systems fixed, Thanks to Andreas Tirok
   06/26/02 - Fix problem with maximum uid number - Thanks to Gerard van Wageningen
   07/02/02 - Minor fixes - Nelson Murilo, nelson@pangeia.com.br
   05/05/14 - Minor fixes - Klaus Steding-jessen 
*/

#if defined(SOLARIS2) || defined(__linux__)
#define HAVE_LASTLOG_H 1
#else
#undef HAVE_LASTLOG_H
#endif
#if __FreeBSD__ > 9
int main () { return 0; }
#else
#include <stdio.h>
#ifdef __linux__
#include <stdlib.h>
#endif
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <utmp.h>
#if (HAVE_LASTLOG_H)
#include <lastlog.h>
#endif
#include <sys/file.h>
#ifdef SOLARIS2
#include <fcntl.h>
#endif

#ifdef __FreeBSD__ 
#define WTMP_FILENAME "/var/log/wtmp"
#define LASTLOG_FILENAME "/var/log/lastlog"
#endif
#ifdef __OpenBSD__
#include <stdlib.h> 
#define WTMP_FILENAME "/var/log/wtmp"
#define LASTLOG_FILENAME "/var/log/lastlog"
#endif
#ifndef WTMP_FILENAME
#define WTMP_FILENAME "/var/adm/wtmp"
#endif
#ifndef LASTLOG_FILENAME
#define LASTLOG_FILENAME "/var/adm/lastlog"
#endif

#define TRUE 1L
#define FALSE 0L

long total_wtmp_bytes_read=0;
size_t wtmp_file_size;
uid_t *uid;
void read_status();

struct s_localpwd {
     int numentries;
     uid_t *uid;
     char  **uname;
};

#ifndef SOLARIS2
int nonuser(struct utmp utmp_ent);
#endif
struct s_localpwd *read_pwd();
void free_results(struct s_localpwd *);
uid_t *localgetpwnam(struct s_localpwd *, char *);
int getslot(struct s_localpwd *, uid_t);

#define MAX_ID 99999

int main(int argc, char*argv[]) {
	int		fh_wtmp;
	int		fh_lastlog;
	struct lastlog	lastlog_ent;
	struct utmp	utmp_ent;
	long		userid[MAX_ID];
	long		i, slot;
	int		status = 0;
	long		wtmp_bytes_read;
	struct stat	wtmp_stat;
	struct s_localpwd	*localpwd;
	uid_t		*uid;
        char wtmpfile[128], lastlogfile[128];

        memcpy(wtmpfile, WTMP_FILENAME, 127);
        memcpy(lastlogfile, LASTLOG_FILENAME, 127);

        while (--argc && ++argv) /* poor man getopt */
        {
           if (!memcmp("-f", *argv, 2))
           {
              if (!--argc)
                 break;
              ++argv;
              memcpy(wtmpfile, *argv, 127);
           }
           else if (!memcmp("-l", *argv, 2))
           {
              if (!--argc)
                 break;
              ++argv;
              memcpy(lastlogfile, *argv, 127);
           }
        }

	signal(SIGALRM, read_status);
	alarm(5);
	for (i=0; i<MAX_ID; i++)
		userid[i]=FALSE;

	if ((fh_lastlog=open(lastlogfile,O_RDONLY)) < 0) {
		fprintf(stderr, "unable to open lastlog-file %s\n", lastlogfile);
		return(1);
	}

	if ((fh_wtmp=open(wtmpfile,O_RDONLY)) < 0) {
		fprintf(stderr, "unable to open wtmp-file %s\n", wtmpfile);
		close(fh_lastlog);
		return(2);
	}
	if (fstat(fh_wtmp,&wtmp_stat)) {
		perror("chklastlog::main: ");
		close(fh_lastlog);
		close(fh_wtmp);
		return(3);
	}
	wtmp_file_size = wtmp_stat.st_size;

	localpwd = read_pwd();

	while ((wtmp_bytes_read = read (fh_wtmp, &utmp_ent, sizeof (struct utmp))) >0) {
            if (wtmp_bytes_read < sizeof(struct utmp))
            {
               fprintf(stderr, "wtmp entry may be corrupted");
               break;
            }
	    total_wtmp_bytes_read+=wtmp_bytes_read;
	    if ( !nonuser(utmp_ent) && strncmp(utmp_ent.ut_line, "ftp", 3) &&
		 (uid=localgetpwnam(localpwd,utmp_ent.ut_name)) != NULL )
            {
                if (*uid > MAX_ID)
                {
                   fprintf(stderr, "MAX_ID is %ld and current uid is %ld, please check\n\r", MAX_ID, *uid );
                   exit (1);

                }
		if (!userid[*uid])
                {
		    lseek(fh_lastlog, (long)*uid * sizeof (struct lastlog), 0);
		    if ((wtmp_bytes_read = read(fh_lastlog, &lastlog_ent, sizeof (struct lastlog))) > 0)
                    {
                        if (wtmp_bytes_read < sizeof(struct lastlog))
                        {
                           fprintf(stderr, "lastlog entry may be corrupted");
                           break;
                        }
                        if (lastlog_ent.ll_time == 0)
                        {
                           if (-1 != (slot = getslot(localpwd, *uid)))
                               printf("user %s deleted or never logged from lastlog!\n",
                                NULL != localpwd->uname[slot] ?
                                (char*)localpwd->uname[slot] : "(null)");
                           else
                              printf("deleted user uid(%d) not in passwd\n", *uid);
                           ++status;
                        }
                        userid[*uid]=TRUE;
                    }
		}
           }
	}
#if 0
	printf("\n");
#endif
	free_results(localpwd);
	close(fh_wtmp);
	close(fh_lastlog);
	return(status);
}

#ifndef SOLARIS2
/* minimal funcionality of nonuser() */
int nonuser(struct utmp utmp_ent)
{
   return (!memcmp(utmp_ent.ut_name, "shutdown", sizeof ("shutdown")));
}
#endif

void read_status() {
   double remaining_time;
   static long last_total_bytes_read=0;
   int diff;

   diff = total_wtmp_bytes_read-last_total_bytes_read;
   if (diff == 0) diff = 1;
   remaining_time=(wtmp_file_size-total_wtmp_bytes_read)*5/(diff);
   last_total_bytes_read=total_wtmp_bytes_read;

   printf("Remaining time: %6.2f seconds\n", remaining_time);
/*
   signal(SIGALRM,read_status);

   alarm(5);
*/
}

struct s_localpwd *read_pwd() {
   struct passwd *pwdent;
   int numentries=0,i=0;
   struct s_localpwd *localpwd;

   setpwent();
   while ((pwdent = getpwent())) {
	numentries++;
   }
   endpwent();
   localpwd = (struct s_localpwd *)malloc((size_t)sizeof(struct s_localpwd));
   localpwd->numentries=numentries;
   localpwd->uid = (uid_t *)malloc((size_t)numentries*sizeof(uid_t));
   localpwd->uname = (char **)malloc((size_t)numentries*sizeof(char *));
   for (i=0;i<numentries;i++) {
      localpwd->uname[i] = (char *)malloc((size_t)30*sizeof(char));
   }
   i=0;
   setpwent();
   while ((pwdent = getpwent()) && (i<numentries)) {
	localpwd->uid[i]=pwdent->pw_uid;
        memcpy(localpwd->uname[i],pwdent->pw_name,(strlen(pwdent->pw_name)>29)?29:strlen(pwdent->pw_name)+1);
	i++;
   }
   endpwent();
   return(localpwd);
}

void free_results(struct s_localpwd *localpwd) {
   int i;
   free(localpwd->uid);
   for (i=0;i<(localpwd->numentries);i++) {
      free(localpwd->uname[i]);
   }
   free(localpwd->uname);
   free(localpwd);
}

uid_t *localgetpwnam(struct s_localpwd *localpwd, char *username) {
   int i;
   size_t len;

   for (i=0; i<(localpwd->numentries);i++) {
      len = (strlen(username)>29)?30:strlen(username)+1;
      if (!memcmp(username,localpwd->uname[i],len)) {
	return &(localpwd->uid[i]);
      }
   }
   return NULL;
}

int getslot(struct s_localpwd *localpwd, uid_t uid)
{
        int i;

        for (i=0; i<(localpwd->numentries);i++)
        {
                if (localpwd->uid[i] == uid)
                        return i;
        }
        return -1;
}
#endif
