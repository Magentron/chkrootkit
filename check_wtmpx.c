/*
 * @(#)check_wtmpx.c 0.02 beta 2001/06/27 NsFocus Copyleft 2001-2010
 *------------------------------------------------------------------------
 * File     : check_wtmpx.c
 * Version  : 0.02 beta
 * Platform : SPARC/Solaris 2.6/7
 * Author   : NsFocus Security Team
 *          : http://www.nsfocus.com
 * Fix      : scz < mailto: scz@nsfocus.com >
 * Compile  : gcc -Wall -O3 -o check_wtmpx check_wtmpx.c
 *          : /usr/ccs/bin/strip check_wtmpx
 *          : /usr/ccs/bin/mcs -d check_wtmpx
 * Date     : 2001-06-27 11:36
 */
#if !defined(__SunOS__) && !defined(SOLARIS2)
int main () { return 0; }
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <time.h>
#include <utmp.h>
#include <utmpx.h>
#include <lastlog.h>
#include <fcntl.h>
#include <unistd.h>

#define WTMP_FILENAME  "/var/adm/wtmp"
#define WTMPX_FILENAME "/var/adm/wtmpx"


struct file_utmp_entry
{
    char        ut_user[8];     /* User login name              */
    char        ut_id[4];       /* /etc/inittab id              */
    char        ut_line[12];    /* device name (console, lnxx)  */
    int16_t     ut_pid;         /* process id                   */
    int16_t     ut_type;        /* type of entry                */
    struct
    {
        int16_t e_termination;  /* Process termination status   */
        int16_t e_exit;         /* Process exit status          */
    } ut_exit;                  /* The exit status of a process */
    uint32_t    ut_time;        /* time entry was made          */
};

struct timeval_32
{
    uint32_t tv_sec;   /* seconds          */
    int32_t  tv_usec;  /* and microseconds */
};

/*
 * This data structure describes the utmp *file* contents using
 * fixed-width data types.  It should only be used by the implementation.
 *
 * Applications should use the getutxent(3c) family of routines to interact
 * with this database.
 */
struct file_utmpx_entry
{
    char              ut_user[32];   /* user login name                */
    char              ut_id[4];      /* inittab id                     */
    char              ut_line[32];   /* device name (console, lnxx)    */
    uint32_t          ut_pid;        /* process id                     */
    int16_t           ut_type;       /* type of entry                  */
    struct
    {
        int16_t e_termination;       /* process termination status     */
        int16_t e_exit;              /* process exit status            */
    } ut_exit;                       /* exit status of a process       */
    struct timeval_32 ut_tv;         /* time entry was made            */
    int32_t           ut_session;    /* session ID, user for windowing */
    int32_t           pad[5];        /* reserved for future use        */
    int16_t           ut_syslen;     /* significant length of ut_host  */
    char              ut_host[257];  /* remote host name               */
};

static void usage ( char * arg )
{
    fprintf( stderr, " Usage: %s [-h] [-w wtmp] [-x wtmpx]\n", arg );
    exit( EXIT_FAILURE );
}  /* end of usage */

int main ( int argc, char * argv[] )
{
    int                     fd_wtmp, fd_wtmpx;
    char                    filename_wtmp[128]  = WTMP_FILENAME;
    char                    filename_wtmpx[128] = WTMPX_FILENAME;
    ssize_t                 wtmp_bytes_read;
    ssize_t                 wtmpx_bytes_read;
    uint32_t                wtmp_read_counter   = 0; 
    uint32_t                wtmpx_read_counter  = 0;
    int                     c;
    struct file_utmp_entry  utmp_entry;
    struct file_utmpx_entry utmpx_entry;

    opterr = 0;  /* Don't want getopt() writing to stderr */
    while ( ( c = getopt( argc, argv, "hw:x:" ) ) != EOF )
    {
        switch ( c )
        {
        case 'w':
            strncpy( filename_wtmp, optarg, 128 );
            filename_wtmp[127]  = '\0';
            break;
        case 'x':
            strncpy( filename_wtmpx, optarg, 128 );
            filename_wtmpx[127] = '\0';
            break;
        case 'h':
        case '?':
            usage( argv[0] );
            break;
        }  /* end of switch */
    }  /* end of while */

    fd_wtmp = open( filename_wtmp, O_RDONLY );
    if ( fd_wtmp < 0 )
    {
        fprintf( stderr, "Unable to open %s\n", filename_wtmp );
        return( EXIT_FAILURE );
    }
    fd_wtmpx = open( filename_wtmpx, O_RDONLY );
    if ( fd_wtmpx < 0 )
    {
        fprintf( stderr, "Unable to open %s\n", filename_wtmpx );
        close( fd_wtmp );
        return( EXIT_FAILURE );
    }
    while ( 1 )
    {
        wtmpx_bytes_read = read( fd_wtmpx, &utmpx_entry, sizeof( struct file_utmpx_entry ) );
        if ( wtmpx_bytes_read > 0 )
        {
            if ( wtmpx_bytes_read < sizeof( struct file_utmpx_entry ) )
            {
                fprintf( stderr, "wtmpx entry may be corrupted\n" );
                break;
            }
            wtmpx_read_counter++;
        }
        wtmp_bytes_read = read( fd_wtmp, &utmp_entry, sizeof( struct file_utmp_entry ) );
        if ( wtmp_bytes_read > 0 )
        {
            if ( wtmp_bytes_read < sizeof( struct file_utmp_entry ) )
            {
                fprintf( stderr, "wtmp entry may be corrupted\n" );
                break;
            }
            wtmp_read_counter++;
        }
        if ( ( wtmpx_bytes_read <= 0 ) || ( wtmp_bytes_read <= 0 ) )
        {
            break;
        }
        if ( strncmp( utmp_entry.ut_user, utmpx_entry.ut_user, 8 ) != 0 )
        {
            fprintf( stderr, "[ %u ] ut_user %s <-> %s\n", wtmp_read_counter, 
                     utmp_entry.ut_user, utmpx_entry.ut_user );
            break;
        }
        if ( memcmp( utmp_entry.ut_id, utmpx_entry.ut_id, 4 ) != 0 )
        {
            fprintf( stderr, "[ %u ] utmp_entry.ut_id != utmpx_entry.ut_id\n", wtmp_read_counter );
            break;
        }
        if ( strcmp( utmp_entry.ut_line, utmpx_entry.ut_line ) != 0 )
        {
            fprintf( stderr, "[ %u ] ut_line %s <-> %s\n", wtmp_read_counter, 
                     utmp_entry.ut_line, utmpx_entry.ut_line );
            break;
        }
        if ( utmp_entry.ut_pid != utmpx_entry.ut_pid )
        {
            fprintf( stderr, "[ %u ] ut_pid %d <-> %d\n", wtmp_read_counter, 
                     utmp_entry.ut_pid, utmpx_entry.ut_pid );
            break;
        }
        if ( utmp_entry.ut_type != utmpx_entry.ut_type )
        {
            fprintf( stderr, "[ %u ] ut_type %d <-> %d\n", wtmp_read_counter, 
                     utmp_entry.ut_type, utmpx_entry.ut_type );
            break;
        }
        if ( utmp_entry.ut_time != utmpx_entry.ut_tv.tv_sec )
        {
            fprintf( stderr, "[ %u ] ut_time %08X <-> %08X\n", wtmp_read_counter, 
                     utmp_entry.ut_time, utmpx_entry.ut_tv.tv_sec );
            break;
        }
    }  /* end of while */
    if ( wtmpx_read_counter != wtmp_read_counter )
    {
        fprintf( stderr, "wtmpx or wtmp entry may be deleted\n" );
    }
    close( fd_wtmpx );
    close( fd_wtmp );
    return( EXIT_SUCCESS );
}  /* end of main */
#endif
