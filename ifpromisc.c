/*
   ifpromisc - This is a simple subset of Fred N. van Kempen,
               <waltje@uwalt.nl.mugnet.org>'s ifconfig and iplink code.
               Show state of all ethernet interfaces
               xxx is PROMISC
               or
               xxx is not promisc

   Version:	@(#)ifpromisc.c	0.8	2003/11/30
   		@(#)ifpromisc.c	0.7	2003/06/07
   Last Changes: Better detection of promisc mode on newer Linux kernels
                 Lantz Moore <lmoore@tump.com>
                 Fix for newer linux kernels, minor fixes
         	 Nelson Murilo, <nelson@pangeia.com.br>
                 Ports for Solaris
                 Andre Gustavo <gustavo@anita.visualnet.com.br>
                 Port for OpenBSD
         	 Nelson Murilo, <nelson@pangeia.com.br>

   Author:	Nelson Murilo, <nelson@pangeia.com.br>
  		Copyright 1997-2003 (C) Pangeia Informatica

  		This program is free software; you can redistribute it
  		and/or  modify it under  the terms of  the GNU General
  		Public  License as  published  by  the  Free  Software
  		Foundation;  either  version 2 of the License, or  (at
  		your option) any later version.
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#ifdef __linux__
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <dirent.h>
#include <sys/stat.h>
#else
#include <net/if.h>
#ifndef __OpenBSD__
#include <net/if_arp.h>
#endif
#endif
#ifdef SOLARIS2
#include <sys/sockio.h>
#endif
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct interface
{
  char			name[IFNAMSIZ];		/* interface name	*/
  short			type;			/* if type		*/
  short			flags;			/* various flags	*/
#ifdef __linux__
  int			index;			/* interface index	*/
#endif
};

char *Release = "chkrootkit package",
     *Version = "@(#) ifpromisc 0.9 (2007/06/15)";
//     *Version = "@(#) ifpromisc 0.8 (2003/11/30)";

int skfd = -1;				/* AF_INET or AF_PACKET raw socket desc.	*/
int q = 0;                              /* Quiet mode on or off				*/

struct packet_info
{
    int index;
    int type;
    int proto;
    int inode;
    char *cmd;
    struct packet_info *next;
};

#ifdef __linux__
/*
 * the contents of /proc/net/packet
 */
static struct packet_info *proc_net_packet = 0;

/*
 * read the entries from /proc/net/packet
 */
static void read_proc_net_packet()
{
    FILE                *proc;
    char                buf[80];

    proc = fopen("/proc/net/packet", "r");
    if (!proc)
    {
        if (errno != ENOENT)
        {
            perror("opening /proc/net/packet");
        }
        return;
    }

    /* skip the header */
    fgets(buf, 80, proc);
    while (fgets(buf, 80, proc))
    {
        int             type = 0;
        unsigned int    proto = 0;
        int             index = 0;
        unsigned int    inode = 0;

        if (sscanf(buf, "%*p %*d %d %x   %d %*d %*u %*u %u",
                  &type, &proto, &index, &inode) == 4)
        {
            struct packet_info *pi;

            pi = (struct packet_info *)malloc(sizeof(struct packet_info));
            pi->type = type;
            pi->proto = proto;
            pi->index = index;
            pi->inode = inode;
            pi->cmd = 0;

            pi->next = proc_net_packet;
            proc_net_packet = pi;
        }
        else
        {
            fprintf(stderr, "cannot grok /proc/net/packet: %s", buf);
        }
    }

    fclose(proc);
}

/* look up an entry from /proc/net/packet by inode */
static struct packet_info *find_packet_info(int inode)
{
    struct packet_info *p;
    for (p = proc_net_packet; p; p = p->next)
    {
        if (p->inode == inode)
        {
            return p;
        }
    }
    return NULL;
}

/* walk a processes fd dir looking for sockets with inodes that match the
 * inodes from /proc/net/packet, when a match is found, the processes exe
 * is stored */
static void walk_process(char *process)
{
    DIR                 *dir;
    struct dirent       *ent;
    char                path[1024];

    if (snprintf(path, sizeof(path), "/proc/%s/fd", process) == -1)
    {
        fprintf(stderr, "giant process name! %s\n", process);
        return;
    }

    if ((dir = opendir(path)) == NULL)
    {
	if (errno != ENOENT)
           perror(path);
        return;
    }

    while ((ent = readdir(dir)))
    {
        struct stat             statbuf;
        struct packet_info     *info;

        if (snprintf(path, sizeof(path), "/proc/%s/fd/%s",
                     process, ent->d_name) == -1)
        {
            fprintf(stderr, "giant fd name /proc/%s/fd/%s\n",
                    process, ent->d_name);
            continue;
        }

        if (stat(path, &statbuf) == -1)
        {
            perror(path);
            continue;
        }

        if (S_ISSOCK(statbuf.st_mode)
            && (info = find_packet_info(statbuf.st_ino)))
        {
            char link[1024];

            memset(link, 0, sizeof(link));
            /* no need to check rv since it has to be long enough,
             * otherwise, one of the ones above will have failed */
            snprintf(path, sizeof(path), "/proc/%s/exe", process);
            readlink(path, link, sizeof(link) - 1);
            info->cmd = strdup(link);
        }
    }

    closedir(dir);
}

/* walk the proc file system looking for processes, call walk_proc on each
 * process */
static void walk_processes()
{
    DIR                 *dir;
    struct dirent       *ent;

    if ((dir = opendir("/proc")) == NULL)
    {
        perror("/proc");
        return;
    }

    while ((ent = readdir(dir)))
    {
        /* we only care about dirs that look like processes */
        if (strspn(ent->d_name, "0123456789") == strlen(ent->d_name))
        {
            walk_process(ent->d_name);
        }
    }

    closedir(dir);

}

/* return 1 if index is a member of pcap_session_list, 0 otherwise. */
static int has_packet_socket(int index)
{
    struct packet_info *p;
    for (p = proc_net_packet; p; p = p->next)
    {
        if (p->index == index)
        {
            return 1;
        }
    }
    return 0;
}
#endif /* __linux__ */

static void ife_print(struct interface *ptr)
{
#ifdef __linux__
    int promisc = ptr->flags & IFF_PROMISC;
    int has_packet = has_packet_socket(ptr->index);

    if (promisc || has_packet)
    {
        printf("%s:", ptr->name);
        if (promisc)
            printf(" PROMISC");
        if (has_packet)
        {
            struct packet_info *p;
            printf(" PF_PACKET(");
            p = proc_net_packet;
            if (p)
            {
                printf("%s", p->cmd);

                for (p = p->next; p; p = p->next)
                {
                    if (p->index == ptr->index)
                    {
                        printf(", %s", p->cmd);
                    }
                }
            }
            printf(")");
        }
        printf("\n");
    }
    else
    {
        if (!q)
            printf("%s: not promisc and no PF_PACKET sockets\n",
                   ptr->name);
    }
#else
   if (ptr->flags & IFF_PROMISC)
      printf("%s is %s", ptr->name, "PROMISC");
   else
   {
      if (!q)
         printf("%s is %s", ptr->name, "not promisc");
   }
   putchar('\n');
#endif
}

/* Fetch the inteface configuration from the kernel. */
static int if_fetch(char *ifname, struct interface *ife)
{
  struct ifreq ifr;

  memset((char *) ife, 0, sizeof(struct interface));
  strncpy(ife->name, ifname, sizeof(ife->name));

  strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
  if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0)
      return(-1);
  ife->flags = ifr.ifr_flags;

#ifdef __linux__
  /* store the device index */
  if (ioctl(skfd, SIOCGIFINDEX, &ifr) < 0)
      return(-1);
  ife->index = ifr.ifr_ifindex;
#endif

  return(0);
}

static void if_print()
{
   char buff[1024];
   struct interface ife;
   struct ifconf ifc;
   struct ifreq *ifr;
   int i;

   ifc.ifc_len = sizeof(buff);
   ifc.ifc_buf = buff;
   if (ioctl(skfd, SIOCGIFCONF, &ifc) < 0)
   {
      fprintf(stderr, "SIOCGIFCONF: %s\n", strerror(errno));
      return;
   }

   ifr = ifc.ifc_req;
   for (i = ifc.ifc_len / sizeof(struct ifreq); --i >= 0; ifr++)
   {
      if (if_fetch(ifr->ifr_name, &ife) < 0)
      {
#ifdef __linux__
         fprintf(stderr, "%s: unknown interface.\n", ifr->ifr_name);
#endif
	 continue;
      }
      if (!memcmp(ifr->ifr_name, "lo", 2))
         continue;
      ife_print(&ife);
   }
}

int main(int argc, char **argv)
{
  if (argc == 2 && !memcmp(argv[1], "-q", 2))
     q++;

  /* Create a channel to the NET kernel. */
   if ((skfd = socket(AF_INET, SOCK_DGRAM,0)) < 0) {
	perror("socket");
	exit(-1);
  }
#ifdef __linux__
  read_proc_net_packet();
  walk_processes();
#endif

  if_print();
  (void) close(skfd);
  exit(0);
}
