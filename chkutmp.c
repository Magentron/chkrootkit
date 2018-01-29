/*
 * 2004/09/23 - Jeremy Miller <jmtgzd@gmail.com>
 *
 * This utility compares the output from the ps command and tries to find
 * a matching entry bound to the same tty in the utmp login records. The
 * idea is to display users that may have wiped themselves from the utmp
 * log.  When analyzing a compromised box, it is assumed you have the
 * path to a known good 'ps' binary in your PATH.
 *
 * LICENSE: This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Changelog:
 *   Ighighi X - Improved speed via break command - 2005/03/27
 *   Some overflow fixes by Michael Schwendt - 2009/07/21
 *   Fixed false warning  - 2017/02/18 - George Ogata
 *
 */

#if !defined(__sun) && !defined(__linux__)
int main () { return 0; }
#else
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <utmp.h>
#include <fcntl.h>
#if defined(__sun)
#include <utmpx.h>
#else
#include <utmp.h>
#endif
#include <ctype.h>

#define MAXREAD 1024
#define MAXBUF 4096
#define MAXLENGTH 256
#define UT_PIDSIZE 12
#if defined(__sun)
#define UTMP "/var/adm/utmpx"
#define UT_LINESIZE 12
#define UT_NAMESIZE 8
#define PS_CMD 0
#else
#define PS_CMD 1
#define UTMP "/var/run/utmp"
#endif

struct ps_line {
    char ps_tty[UT_LINESIZE];
    char ps_user[UT_NAMESIZE];
    char ps_args[MAXLENGTH];
    int ps_pid;
};
struct utmp_line {
    char ut_tty[UT_LINESIZE];
    int ut_pid;
    int ut_type;
};
static char *cmd[] = {
    "ps -ef -o \"tty,pid,ruser,args\"",	/* solaris */
    "ps ax -o \"tty,pid,ruser,args\""	/* linux */
};
int fetchps(struct ps_line *);
int fetchutmp(struct utmp_line *);

int fetchps(struct ps_line *psl_p)
{
    FILE *ps_fp;
    char line[MAXREAD + 1], pid[UT_PIDSIZE];
    char *s, *d;
    struct ps_line *curp = &psl_p[0];
    struct ps_line *endp = &psl_p[MAXBUF-1];
    int i, x, line_length;

    i = 0;
    if ((ps_fp = (popen(cmd[PS_CMD], "r"))) != NULL) {
	fgets(line, MAXREAD, ps_fp);	/* skip header */
	while (fgets(line, MAXREAD, ps_fp)) {
	    s = line;
	    if (*s != '\?' && curp <= endp) {	/* only interested in lines that
						 * have a tty */
		d = curp->ps_tty;
		for (x = 0; (!isspace(*s)) && (*d++ = *s++) && x <= UT_LINESIZE; x++)	/* grab tty */
		    ;
		*d = '\0';
		while (isspace(*s))	/* skip spaces */
		    s++;
		d = pid;
		for (x = 0; (!isspace(*s)) && (*d++ = *s++) && x <= UT_LINESIZE; x++)	/* grab pid */
		    ;
		*d = '\0';
		curp->ps_pid = atoi(pid);
		while (isspace(*s))	/* skip spaces */
		    s++;
		d = curp->ps_user;
		for (x = 0; (!isspace(*s)) && (*d++ = *s++) && x <= UT_NAMESIZE; x++)	/* grab user */
		    ;
		*d = '\0';
		d = curp->ps_args;
		while (isspace(*s))	/* skip spaces */
		    s++;
		for (x = 0; (*d++ = *s++) && x <= MAXLENGTH; x++)	/* cmd + args */
		    ;
		i++;
		curp++;
                /* if we didn't read the line, skip the rest */ 
                line_length = strlen(line); 
                while (!(line_length == 0 || line[line_length -1] == '\n')) { 
                   fgets(line, MAXREAD, ps_fp);
                   line_length = strlen(line); 
                } 
	    }
	}
	pclose(ps_fp);
    } else {
	fprintf(stderr, "\nfailed running 'ps' !\n");
	exit(EXIT_FAILURE);
    }
    return i;
}

int fetchutmp(struct utmp_line *utl_p)
{
#if defined(__sun)
    struct utmpx ut;
#else
    struct utmp ut;
#endif
    struct utmp_line *curp = &utl_p[0];
    struct utmp_line *endp = &utl_p[MAXBUF-1];
    int i, f, del_cnt, sz_ut;

    i = del_cnt = 0;
    if ((f = open(UTMP, O_RDONLY)) > 0) {
#if defined(__sun)
	sz_ut = sizeof(struct utmpx);
#else
	sz_ut = sizeof(struct utmp);
#endif

	while (read(f, &ut, sz_ut) > 0 && curp <= endp) {
#if !defined(__sun)
	    if (ut.ut_time == 0)
		del_cnt++;	/* ut_time shouldn't be zero */
#endif
	    if (strlen(ut.ut_user) > 0) {
		strncpy(curp->ut_tty, ut.ut_line, UT_LINESIZE);
		curp->ut_pid = ut.ut_pid;
		curp->ut_type = ut.ut_type;
		i++;
		curp++;
	    }
	}
	close(f);
	if (del_cnt > 0)
	    printf("=> possibly %d deletion(s) detected in %s !\n",
		   del_cnt, UTMP);
    } else {
	fprintf(stderr, "\nfailed opening utmp !\n");
	exit(EXIT_FAILURE);
    }
    return i;
}

int main(int argc, char *argv[])
{
    struct ps_line ps_l[MAXBUF];	/* array of data from 'ps' */
    struct utmp_line ut_l[MAXBUF];	/* array of data from utmp log */
    int h, i, y, z, mtch_fnd, hdr_prntd;

    y = fetchps(ps_l);
    z = fetchutmp(ut_l);
    hdr_prntd = 0;
    for (h = 0; h < y; h++) {	/* loop through 'ps' data */
	mtch_fnd = 0;
	for (i = 0; i < z; i++) {	/* try and match the tty from 'ps' to one in utmp */
	    if (ut_l[i].ut_type == LOGIN_PROCESS	/* ignore getty processes with matching pid from 'ps' */
		&& ut_l[i].ut_pid == ps_l[h].ps_pid)
	   {
		mtch_fnd = 1;
	        break;
           }
	    else if (strncmp(ps_l[h].ps_tty, ut_l[i].ut_tty,	/* compare the tty's */
			     strlen(ps_l[h].ps_tty)) == 0)
	    {
		mtch_fnd = 1;
	        break;
	    }
	}
	if (!mtch_fnd) {
	    if (!hdr_prntd) {
		printf
		    (" The tty of the following user process(es) were not found\n");
		printf(" in %s !\n", UTMP);
		printf("! %-9s %7s %-6s %s\n", "RUID", "PID", "TTY",
		       "CMD");
		hdr_prntd = 1;
	    }
	    printf("! %-9s %7d %-6s %s", ps_l[h].ps_user,
		   ps_l[h].ps_pid, ps_l[h].ps_tty, ps_l[h].ps_args);
	}
    }
    exit(EXIT_SUCCESS);
}
#endif
