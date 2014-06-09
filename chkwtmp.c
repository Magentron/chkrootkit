/*
   Copyright (c) DFN-CERT, Univ. of Hamburg 1994

   Univ. Hamburg, Dept. of Computer Science
   DFN-CERT
   Vogt-Koelln-Strasse 30
   22527 Hamburg
   Germany

   02/20/97 - Minimal changes for Linux/FreeBSD port.
   Nelson Murilo, nelson@pangeia.com.br
   09/07/00 - Ports for Solaris
   Andre Gustavo <gustavo@anita.visualnet.com.br>
   12/15/00 - Add -f option
   Nelson Murilo, nelson@pangeia.com.br
   07/08/04 - fix del counter value (Thanks to Dietrich Raisin)
   Nelson Murilo, nelson@pangeia.com.br
   09/12/05 - fix Segfault (Thanks to Jérémie Andréi)
   Nelson Murilo, nelson@pangeia.com.br
*/

#if __FreeBSD__ > 9 
int main () { return 0; } 
#else
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <utmp.h>
#include <time.h>
#include <sys/time.h>
#include <sys/file.h>
#ifdef SOLARIS2
#include <fcntl.h>
#endif

#ifdef __FreeBSD__
#define WTMP_FILENAME "/var/log/wtmp"
#else
#ifndef WTMP_FILENAME
#define WTMP_FILENAME "/var/adm/wtmp"
#endif
#endif

void printit(counter, start, end)
int counter;
long start,end;
{
	char		buffer[30];

	printf("%d deletion(s) between ", counter);
	strncpy(buffer, ctime( (time_t *) &start), 30);
	buffer[24]='\0';
	printf("%s and %s", buffer, ctime( (time_t *) &end));
}


int main(int argc, char*argv[]) {
	int		filehandle;
	struct utmp	utmp_ent;
	struct timeval	mytime;
	struct timezone	dummy;
	long		start_time, act_time;
	int		del_counter, t_del;
        char wtmpfile[128];

	del_counter=t_del=0;
	start_time=0;

	gettimeofday(&mytime, &dummy);
       act_time=mytime.tv_sec;
       wtmpfile[127]='\0';
       memcpy(wtmpfile, WTMP_FILENAME, 127);
       if ( argc == 3 && !memcmp("-f", argv[1], 2) && *argv[2])
          memcpy(wtmpfile, argv[2], 127);

	if ((filehandle=open(wtmpfile,O_RDONLY)) < 0) {
		fprintf(stderr, "unable to open wtmp-file %s\n", wtmpfile);
		return(2);
	}

	while (read (filehandle, (char *) &utmp_ent, sizeof (struct utmp)) > 0) {
		if (utmp_ent.ut_time == 0)
			del_counter++;
		else {
			if (del_counter) {
				printit(del_counter, start_time,
					utmp_ent.ut_time);
				t_del++;
				del_counter=0;
			}
			start_time=utmp_ent.ut_time;
		}
	}
	close(filehandle);
	if (del_counter)
	   printit(del_counter, start_time, act_time);
        exit((int) t_del+del_counter);
}
#endif
