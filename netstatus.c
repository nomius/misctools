
/* vim: set sw=4 sts=4 tw=80 */

/*
 * Copyright (c) 2014 , David B. Cortarello <dcortarello@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    This product includes software developed by David B. Cortarello.
 * 4. Neither the name of David B. Cortarello nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID B. CORTARELLO 'AS IS' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL DAVID B. CORTARELLO BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * NOTES:
 * You can set up this in conky this way:
 * ${color white}${execi 5 sudo /usr/bin/killall -SIGHUP netstatus; /bin/sleep 1; /usr/bin/tac /var/log/netstat.log | /usr/bin/head -n 1 | /usr/bin/grep CURRENT} ${hr 1}${color}
 *
 * ${color red}${execi 10 /usr/bin/tail -n 5 /var/log/netstat.log | /usr/bin/grep -v CURRENT}
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#define PACKETSIZE  64
#define DATE_SIZE 22
#define MAX_DOWNS 5
#define LOGFILE "/var/log/netstat.log"

struct packet {
	struct icmphdr hdr;
	char msg[PACKETSIZE - sizeof(struct icmphdr)];
};

int bump = 0;

void write_log(int status)
{
	FILE *f;
	time_t now;
	struct tm *tt;

	if ((f = fopen(LOGFILE, "a+"))) {
		now = time(NULL);
		tt = localtime(&now);

		fprintf(f, "CURRENT NETWORK STATUS: %s\n", status < 0 ? "DOWN" : "UP");
		fclose(f);
	}
	bump = 0;
}

void record_change(char *new_state)
{
	char logdown[DATE_SIZE + 64];
	FILE *f;
	time_t now;
	struct tm *tt;

	if ((f = fopen(LOGFILE, "a+"))) {
		now = time(NULL);
		tt = localtime(&now);

		fprintf(f, "%d/%0.2d/%0.2d (%0.2d:%0.2d:%0.2d) - status change [%s]\n", \
				1900 + tt->tm_year, \
				tt->tm_mon, \
				tt->tm_mday, \
				tt->tm_hour, \
				tt->tm_min, \
				tt->tm_sec, \
				new_state);
		fclose(f);
	}
}

void bump_log(int sig) {
	bump = 1;
}

unsigned short checksum(void *b, int len)
{
	unsigned short *buf = b;
	unsigned int sum = 0;
	unsigned short result;

	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;
	if (len == 1)
		sum += *(unsigned char *)buf;
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

void ping(char *address)
{
	const int val = 255;
	int i, sd, loop, pid, cnt = 1, len = 0, ret = 0, predown = 0, down = 1;
	struct packet pckt;
	struct hostent *hname;
	struct sockaddr_in addr_ping, *addr, r_addr;
	struct protoent *proto = NULL;

	pid = getpid();
	if (!(proto = getprotobyname("ICMP"))) {
		/*herror("getprotobyname");*/
		exit(1);
	}

	while (1) {

		if (down) {
			if (!(hname = gethostbyname(address))) {
				/*herror("gethostbyname");*/
				sleep(3);
				ret = 1;
				goto log;
			}

			memset(&addr_ping, '\0', sizeof(addr_ping));
			addr_ping.sin_family = hname->h_addrtype;
			addr_ping.sin_port = 0;
			addr_ping.sin_addr.s_addr = *(long *)hname->h_addr;
			addr = &addr_ping;

			if ((sd = socket(PF_INET, SOCK_RAW, proto->p_proto)) < 0) {
				/*perror("socket");*/
				sleep(3);
				ret = 1;
				goto log;
			}
			if (setsockopt(sd, SOL_IP, IP_TTL, &val, sizeof(val)) != 0) {
				/*perror("Set TTL option");*/
				sleep(3);
				ret = 1;
				goto log;
			}
			if (fcntl(sd, F_SETFL, O_NONBLOCK) != 0) {
				/*perror("Request nonblocking I/O");*/
				sleep(3);
				ret = 1;
				goto log;
			}
		}

		memset(&pckt, '\0', sizeof(pckt));
		pckt.hdr.type = ICMP_ECHO;
		pckt.hdr.un.echo.id = pid;
		memset(pckt.msg, '0', sizeof(pckt.msg) - 1);
		pckt.hdr.un.echo.sequence = cnt++;
		pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

		if (sendto(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)addr, sizeof(*addr)) <= 0) {
			/*perror("sendto");*/
			ret = -1;
			goto log;
		}
		else {
			sleep(1);

			len = sizeof(r_addr);

			ret = recvfrom(sd, &pckt, sizeof(pckt), 0, (struct sockaddr *)&r_addr, &len);

			if (bump)
				write_log(ret);
		}

log:
		if (ret < 0) {
			down = 1;
			if (down != predown) {
				record_change("DOWN");
				predown = down = 1;
			}
		}
		else {
			down = 0;
			if (down != predown) {
				record_change("UP");
				down = predown = 0;
			}
		}
		sleep(1);
	}
}

int main(int argc, char *argv[])
{
	signal(SIGHUP, bump_log);
	signal(SIGINT, exit);
	signal(SIGTERM, exit);

	if (argv[1] != NULL)
		ping(argv[1]);

	return 0;
}
