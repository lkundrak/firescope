/* firescope - simple interface to Linux kernels over firewire 
   Originally from Ben Herrenschmidt, hacked by Andi Kleen.
   Subject to the GNU General Public License, v.2 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <ctype.h>
#include <poll.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <libraw1394/raw1394.h>

#include "firescope.h"

FILE *logfile;

int verbose = 0;
int rem_ptrsize = sizeof(void *);
int auto_update;
int cookedtty;

raw1394handle_t		g_handle;
nodeid_t		g_target;
int			g_target_ok;
u_int64_t		g_target_uid;
int			g_change_occurred;
char*			g_sysmap;
size_t			g_sysmap_size;
int			g_attached;
int			g_machine;
unsigned long		g_init_cpu_mask;
unsigned long		g_xmon_cpu_mask_addr;
unsigned		g_xmon_cpu_mask;
static char		g_local_buf[1024+4];

unsigned long		log_buf;
unsigned long		log_buf_len;
unsigned long		log_end;
nodeaddr_t		log_end_addr;
nodeaddr_t		logged_chars_addr;
long			logged_chars;
char *			log_buf_shadow;

#define XMON_FW_FLAGS_OUT_ENTERED	0x00000001
#define XMON_FW_FLAGS_OUT_DATA		0x00000002
#define XMON_FW_FLAGS_OUT_ACK		0x00000004
#define XMON_FW_FLAGS_IN_ATTACHED	0x00000001
#define XMON_FW_FLAGS_IN_DATA		0x00000002
#define XMON_FW_FLAGS_IN_ACK		0x00000004
static unsigned long		g_xmon_outbuf_addr;
static unsigned long		g_xmon_outbuf_size_addr;
static unsigned long		g_xmon_iflags_addr;
static unsigned long		g_xmon_oflags_addr;
static unsigned long		g_xmon_idata_addr;
static unsigned long		g_xmon_kick_addr;

static struct termios g_norm_tio;
static struct termios g_raw_tio;

static unsigned long long find_symbol(const char* symbol, int sym_type, int *length);


static void
need_console(void)
{
	if (cookedtty)
		return;
	tcsetattr(STDIN_FILENO, TCSANOW, &g_norm_tio);
}

static void
restore_console(void)
{
	if (cookedtty)
		return;
	fflush(stdout);
	tcsetattr(STDIN_FILENO, TCSANOW, &g_raw_tio);
}

static int
got_bus_reset(raw1394handle_t hndl, unsigned int generation)
{
	raw1394_update_generation(g_handle, generation);
	g_target_ok = 0;
	g_attached = 0;
	g_change_occurred = 1;
	printf("Bus reset !\n\r");
	return 0;
}

static int
setup_handle(int port_num)
{
	int port_count;
	struct raw1394_portinfo ports[16];
	
	g_handle = raw1394_new_handle();
	if (!g_handle) {
		perror("libraw1394 couldn't be initialized");
		return -1;
	}

	port_count = raw1394_get_port_info(g_handle, ports, 16);
	if (port_count <= port_num) {
		fprintf(stderr, "Port %d not available (%d ports detected).\n", port_num, port_count);
		return -1;
	}
	raw1394_set_port(g_handle, port_num);
	printf("Port %d (%s) opened, %d nodes detected\n", port_num,
		ports[port_num].name, ports[port_num].nodes);

	raw1394_set_bus_reset_handler(g_handle, got_bus_reset);

	return 0;
}

static void
select_target(int target)
{
	int i, tgt, count, local;

	count = raw1394_get_nodecount(g_handle);
	local = raw1394_get_local_id(g_handle) & 0x3f;
	
	need_console();
	printf("%d nodes available, local node is: %d\n", count, local);
	for (i=0; i<count; i++) {
		quadlet_t uuid[2];
		int rc;

		printf(" %d: %04x, uuid: ", i, i | 0xffc0);
		rc = raw1394_read(g_handle, i | 0xffc0, CSR_BASE + 0x40c, 4, &uuid[0]);
		if (rc >= 0)
			rc = raw1394_read(g_handle, i | 0xffc0, CSR_BASE + 0x410, 4, &uuid[1]);
		if (rc < 0)
			printf("<err: %d>", errno);
		else
			printf("%08x %08x", uuid[0], uuid[1]);
		if (i == local)
			printf(" [LOCAL]");
		printf("\n");
	}
	if (target != -1) { 
		if (target == -2) { 
			int max = raw1394_get_nodecount(g_handle);
			for (target = 0; target < max; target++)
				if (target != local)
					break;
			if (target == local) { 
				printf("No non local target found\n\r");
				need_console();
				exit(1);
			}
		}
			
		tgt = target;
	} else {
		printf("pick a target node: ");
		scanf("%d", &tgt);
	}
	if (tgt < 0 || tgt >= raw1394_get_nodecount(g_handle))
		printf("wrong node number !\n");
	else if (tgt == local)
		printf("can't pick local node !\n");
	else {
		g_target = tgt | 0xffc0;
		g_target_ok = 1;
	}
	g_change_occurred = 1;
	restore_console();
}

static void
menu_show(void)
{
	need_console();
	printf("\nFireScope\n---------\n");
	printf("Target : ");
	if (g_target_ok)
		printf("%04x\n", g_target);
	else
		printf("<unspecified>\n");
	printf("Gen    : %d\n", raw1394_get_generation(g_handle));
		
	printf("[Ctrl-T] choose target \n");
	if (g_target_ok) {
		printf("[Ctrl-R] read symbol\n");
		printf("[Ctrl-W] write symbol\n");
		printf("[Ctrl-A] attach to kernel\n");
	}
	if (g_attached && g_machine) { 
		printf("[Ctrl-O] stop at next timer irq\n");
		printf("[Ctrl-C] catch CPU (reset it)\n");
	}
	if (log_buf_shadow) { 
		printf("[Ctrl-D] display kernel log\n");
		printf("[Cltr-U] update kernel log automatically\n"
		       "Press again to disable\n");
	}		       
	printf("[Ctrl-H] this menu\n");
	printf("[Ctrl-Q] quit\n");
	restore_console();
}

unsigned long parse_symbol(char *p, int *length) 
{ 
	unsigned long addr = 0;
	int virt = 1;
	int dummy;

	*length = 4;
#ifdef __ppc__
	if (toupper(*p) == 'C' && isdigit(p[1])) {
		addr = CSR_BASE;
		p++;
	}
#endif
	if (toupper(*p) == 'P' && isdigit(p[1])) {
		virt = 0;
		p++;
	}
	
	char *dash = strchr(p, '/');
	if (dash != NULL) {
		*dash++ = 0;
		*length = strtoul(dash, NULL, 0);
		length = &dummy;
	}

	if (isalpha(*p) || *p == '_') {
		printf("Looking for %s\n\r", p);
		addr = find_symbol(p,sym_data|sym_bss|sym_text, length);
		if (!addr) {
			printf("Symbol %s not found\n\r",p);
			return 0;
		}
		virt = 1;
	} else {
		addr += strtoull(p, &p, 0);	
	}
	if (virt) 
		addr = virt_to_phys(addr);
	return addr;
} 

static void
read_quadlet(void)
{
	nodeaddr_t addr;
	char tmp[128];
	int length;

	need_console();
	printf("Read from [address[/length]]: ");
	scanf("%128s", tmp);
	addr = parse_symbol(tmp, &length);	

	// XXX unaligned handling
	char buf[length];
	if (rem_readblk(buf, addr, length) < 0) {
#if 0
		printf("Failed\n\r");
		restore_console();
		return;
#endif
	}

	switch (length) {
	case 4:	printf("%lx: %x\n\r", addr, *((unsigned *)buf)); break;
	case 1:	printf("%lx: %x\n\r", addr, *((unsigned char *)buf)); break;
	case 2:	printf("%lx: %x\n\r", addr, *((unsigned short *)buf)); break;
	case 8:	printf("%lx: %Lx\n\r", addr, *((unsigned long long *)buf)); 
		break;
	default: { 
		int i;
		for (i = 0; i < length; i++) {
			if (i % 20 == 0)
				printf("%lx: ", addr + i); 
			printf("%02x ", buf[i]);
			if (i % 20 == 19)
				printf("\n\r");
		}
		printf("\n\r");
		break;
	}
	}
	restore_console();
}

static void
write_quadlet(void)
{
	nodeaddr_t addr;
	quadlet_t quad;
	int rc;
	char tmp[128];
	char datastr[128];
	
	need_console();
	printf("Write to [address,data]: ");
	scanf("%128s %128s", tmp, datastr);
	int length;
	addr = parse_symbol(tmp,&length);
	printf("Address %lx\n\r", addr);
	quad = strtoull(datastr, NULL, 0);
	rc = raw1394_write(g_handle, g_target, addr, 4, &quad);
	if (rc < 0)
		perror("write failed");
	else
		printf("Quadlet at 0x%lx is: 0x%lx\n", (long)addr, (long)quad);
	restore_console();
}

static unsigned long long
__find_symbol(const char* symbol, int *sym_type, int exact, int *length)
{
	const char *p, *cur;
	const char *match;
	int goodness = 0;
	unsigned long long result = 0;
	
	if (!g_sysmap || !g_sysmap_size)
		return 0;

	cur = g_sysmap;
	while(cur) {
		cur = strstr(cur, symbol);
		if (cur) {
			int gd = 1;

			/* best match if equal, better match if
			 * begins with
			 */
			if (cur == g_sysmap || *(cur-1) == ' ') {
				gd++;
				if (cur[strlen(symbol)] == 10)
					gd++;
			}
			if (gd == 3 || (!exact && gd > goodness)) {
				match = cur;
				goodness = gd;
				if (gd == 3)
					break;
			}
			cur++;
		}
	}	
	if (goodness) {
		p = match;
		while(p > g_sysmap && *p != 10)
			p--;
		if (*p == 10) p++;
		errno = 0;
		result = strtoull(p, (char **)&p, 16);
		if (errno == ERANGE) {
			printf("Symbol %s out of range. Non matching pointer size?\n",symbol);
			return 0;
		}
		if (result > 0xffffffff) 
			rem_ptrsize = 8; 
		else
			rem_ptrsize = 4;
			
		if (sym_type) {
			while(*p == ' ')
				p++;
			switch(toupper(*p)) {
				case 'T': *sym_type = sym_text; break;
				case 'D': *sym_type = sym_data; break;
				case 'B': *sym_type = sym_bss; break;
				default:  *sym_type = sym_bad; break;
			}
		}

		if (length) { 
			while (isspace(*p)) p++;
			while (*p && *p != '\n') p++;
			if (*p == '\n') p++;
			unsigned long nextaddr = strtoul(p, NULL, 16);
			*length = nextaddr - result;
		}
	}
	return result;
}		

static unsigned long long
find_symbol(const char* symbol, int sym_type, int *length)
{
	int found_type;
	unsigned long long result;
	
	result = __find_symbol(symbol, &found_type, 1, length);
	if (result && ((found_type & sym_type) == 0))
		result = 0;
	return result;
}

static void
read_xmon_output(void)
{
	unsigned int oflags, i, len;
	
	if (g_xmon_outbuf_addr == 0)
		return;

	rem_writel(virt_to_phys(g_xmon_iflags_addr), XMON_FW_FLAGS_IN_ATTACHED);
	oflags = rem_readl(virt_to_phys(g_xmon_oflags_addr));
	if ((oflags & XMON_FW_FLAGS_OUT_DATA) == 0)
		return;
	len = rem_readl(virt_to_phys(g_xmon_outbuf_size_addr));
	rem_readblk(g_local_buf, virt_to_phys(g_xmon_outbuf_addr), len);
	rem_writel(virt_to_phys(g_xmon_iflags_addr),
		XMON_FW_FLAGS_IN_ATTACHED | XMON_FW_FLAGS_OUT_ACK);
	for (i=0; i<100; i++) {
		oflags = rem_readl(virt_to_phys(g_xmon_oflags_addr));
		if ((oflags & XMON_FW_FLAGS_OUT_DATA) == 0)
			break;
		usleep(1000);
	}
	rem_writel(virt_to_phys(g_xmon_iflags_addr), XMON_FW_FLAGS_IN_ATTACHED);
	if (oflags & XMON_FW_FLAGS_OUT_DATA)
		printf("<timeout reading xmon data>\r\n");
	if (len) {
		char*p = g_local_buf;
		g_local_buf[len] = 0;
		for (i=0; i<len; i++) {
			if (g_local_buf[i] == 10) {
				g_local_buf[i] = 0;
				printf("%s\n\r", p);
				p = &g_local_buf[i+1];
			}
		}
		printf("%s", p);
		fflush(stdout);
		
	}
}
	

static void
send_xmon_key(char key)
{
	unsigned int oflags, i;

	if (!g_xmon_outbuf_addr)
		return;
	oflags = rem_readl(virt_to_phys(g_xmon_oflags_addr));
	if ((oflags & XMON_FW_FLAGS_OUT_ENTERED) == 0)
		return;
	rem_writel(virt_to_phys(g_xmon_idata_addr), (unsigned long)key);
	rem_writel(virt_to_phys(g_xmon_iflags_addr),
		XMON_FW_FLAGS_IN_ATTACHED | XMON_FW_FLAGS_IN_DATA);
	for (i=0; i<1000; i++) {
		oflags = rem_readl(virt_to_phys(g_xmon_oflags_addr));
		if ((oflags & XMON_FW_FLAGS_OUT_ACK) != 0)
			break;
		if ((oflags & XMON_FW_FLAGS_OUT_DATA) != 0) {
			read_xmon_output();
			rem_writel(virt_to_phys(g_xmon_iflags_addr),
				XMON_FW_FLAGS_IN_ATTACHED | XMON_FW_FLAGS_IN_DATA);
			i = 0;
			continue;
		}
		usleep(1000);
	}
	rem_writel(virt_to_phys(g_xmon_iflags_addr), XMON_FW_FLAGS_IN_ATTACHED);
	if ((oflags & XMON_FW_FLAGS_OUT_ACK) == 0)
		goto timeout;
	for (i=0; i<1000; i++) {
		oflags = rem_readl(virt_to_phys(g_xmon_oflags_addr));
		if ((oflags & XMON_FW_FLAGS_OUT_ACK) == 0)
			break;
		usleep(1000);
	}
	if ((oflags & XMON_FW_FLAGS_OUT_ACK) != 0)
		goto timeout;
	return;
timeout:
	printf("<timeout sending xmon data>\r\n");
}

static void
update_remote_data(int initial)
{
	unsigned long cur_mask;
	int i;
	
	if (g_xmon_cpu_mask_addr)
		cur_mask = rem_readl(virt_to_phys(g_xmon_cpu_mask_addr));
	else if (g_xmon_oflags_addr) {
		cur_mask = rem_readl(virt_to_phys(g_xmon_oflags_addr));
		cur_mask &= XMON_FW_FLAGS_OUT_ENTERED;
	} else
		return;
		
	if (cur_mask != g_xmon_cpu_mask) {
		for (i=0; i<NR_CPUS; i++) {
			if ((cur_mask & (1 << i)) && !(g_xmon_cpu_mask & (1 << i)))
				printf("CPU %d %s xmon\r\n", i, initial ? "is in" : "entered");
			else if ((g_xmon_cpu_mask & (1 << i)) && !(cur_mask & (1 << i)))
				printf("CPU %d left xmon\r\n", i);
		}
		g_xmon_cpu_mask = cur_mask;
	}

	read_xmon_output();
}

static int fetch_kernel_log(void)
{
	if (!log_buf_shadow) { 
		need_console();
		printf("No kernel log buffer\n\r"); 
		restore_console();
		return -1;
	}
	log_end = rem_readl(log_end_addr);
	log_end %= log_buf_len;
	if (log_end == -1) { 
		need_console();
		printf("Cannot read log start. Target in bad state?\n\r");
		restore_console();
		free(log_buf_shadow);
		log_buf = 0;
		return -1;
	}		
	if (rem_ptrsize == 8)
		logged_chars = rem_readq(logged_chars_addr);
	else
		logged_chars = rem_readl(logged_chars_addr);
	if (logged_chars > log_buf_len)
		logged_chars = log_buf_len;
	return 0;
}

static int output_log(unsigned start, unsigned end, int skiptoline) 
{ 
	need_console();
	unsigned rstart = start > 3 ? (start - 3) & ~3UL : 0;
	unsigned rend = (end + 3) & ~3UL;
	if (rem_readblk(log_buf_shadow + rstart, log_buf + rstart, rend - rstart) < 0) 
		return 0;
	int i;
	if (skiptoline) { 
		for (i = start; i < end; i++) 
			if (log_buf_shadow[i] == '\n') {
				start = i;
				break;
			}
	}
	// XXX someone who understands terminals better than me
	// should figure out how to get rid of the extraneous 
	// newlines
	fwrite(log_buf_shadow + start, 1, end-start, stdout);
	if (logfile)
		fwrite(log_buf_shadow + start, 1, end-start, logfile);
	restore_console();
	return 1;
} 

static void __display_dmesg(unsigned l, int skiptoline)
{
	// should read backwards like the kernel code
	// or catch races by  rechecking the variables
	if (l > log_end) {
		if (output_log(0, log_end, skiptoline)) 
			skiptoline = 0;
		l -= log_end;
		output_log(log_buf_len - l, log_buf_len, skiptoline);
	} else { 
		output_log(log_end - l, log_end, skiptoline);
	} 
}

static void display_dmesg(void)
{
	if (fetch_kernel_log() < 0)
		return;
	__display_dmesg(logged_chars, 0);
}

int first_update;

static void update_dmesg(void)
{
	unsigned old_log_end = log_end;
	if (fetch_kernel_log() < 0) 
		return;
	if (0 && log_end != old_log_end)
		printf("log_end %d old_log_end %d\n\r", log_end, old_log_end);
	if (first_update != 0 && !cookedtty) { 
		__display_dmesg(300, 1);
		first_update = 0;
	} else if (log_end > old_log_end) { 
		__display_dmesg(log_end - old_log_end + 1, 0);
	} else if (log_end < old_log_end) { /* wrapping */
		printf("<W>"); 
		__display_dmesg(log_end + (log_buf_len - old_log_end) + 1, 0);
	} /* else nothing to dump */
}

static void lookup_kernel_log(void)
{
	unsigned long long log_buf_addr = find_symbol("log_buf", sym_data|sym_bss,NULL);
#define C(x)  if (!x) { printf("Cannot lookup %s\n\r", #x); goto out; } 
	C(log_buf_addr);
	unsigned long long log_buf_len_addr = find_symbol("log_buf_len", sym_data|sym_bss,NULL);
	C(log_buf_len_addr);
	log_end_addr = find_symbol("log_end", sym_data|sym_bss,NULL);	
	C(log_end_addr);
	logged_chars_addr = find_symbol("logged_chars", sym_data|sym_bss,NULL);
#undef C

	log_buf = virt_to_phys(rem_readptr(virt_to_phys(log_buf_addr)));
	log_buf_len = rem_readl(virt_to_phys(log_buf_len_addr));
	log_end_addr = virt_to_phys(log_end_addr);
	logged_chars_addr = virt_to_phys(logged_chars_addr);

	need_console();
	printf("kernel buffer at phys %lx len %lu\n\r", log_buf, log_buf_len);

	log_buf_shadow = malloc(log_buf_len);
	if (!log_buf_shadow) {
		printf("Cannot allocate log_buf shadow of %lu bytes\n",
		       log_buf_len);
	}
	restore_console();
	first_update = 1;
	return;

out:
	printf("Cannot find linux log buffer\n\r");
}

static void
attach_kernel(void)
{
	unsigned long target_addr;
	
	if (!g_target_ok)
		return;

	g_init_cpu_mask = 0;
	g_xmon_cpu_mask = 0;
	g_attached = 0;
	
	need_console();
	lookup_kernel_log();
	target_addr = find_symbol("_machine", sym_data | sym_bss,NULL);
	if (target_addr == 0) {
#ifdef __ppc__ 
		printf("It's not a ppc (Can't find _machine in System.map)\n\r");
#endif
	} else 
		{
		printf("Got _machine at %x, reading %lx...\n",
			target_addr, (long)virt_to_phys(target_addr));
		g_machine = rem_readl(virt_to_phys(target_addr));
		printf("g_machine: %x\n", g_machine);
		switch(g_machine) {
			case 1:
				printf("Found PReP kernel\n"); break;
			case 2:
				printf("Found PMac kernel\n"); break;
			case 4:
				printf("Found CHRP kernel\n"); break;
			default:
				printf("Unrecognized kernel type\n");
				return;
		}
		g_attached = 1;
	}
	if (!g_attached) {
		restore_console();
		return;
	}
	target_addr = find_symbol("cpu_callin_map", sym_data | sym_bss,NULL);
	if (target_addr) {
		int i;

		g_xmon_cpu_mask_addr = find_symbol("cpus_in_xmon", sym_data | sym_bss,NULL);
		for (i=0; i<NR_CPUS; i++) {
			int enabled = rem_readl(virt_to_phys(target_addr + i*4));
			if (enabled)
				g_init_cpu_mask |= 1 << i;
		}
		printf("Found SMP kernel, CPU mask: %08lx\n", g_init_cpu_mask);
		if (!g_xmon_cpu_mask_addr)
			printf("Kernel don't have xmon compiled in !\n");
	
	} else {
		printf("Kernel appears to be UP\n");
		g_init_cpu_mask = 1;
	}
	g_xmon_outbuf_addr = find_symbol("xmon_fw_outbuf", sym_data | sym_bss,NULL);
	if (g_xmon_outbuf_addr) {
		g_xmon_outbuf_size_addr = find_symbol("xmon_fw_outbuf_size", sym_data | sym_bss,NULL);
		g_xmon_iflags_addr = find_symbol("xmon_fw_iflags", sym_data | sym_bss,NULL);
		g_xmon_oflags_addr = find_symbol("xmon_fw_oflags", sym_data | sym_bss,NULL);
		g_xmon_idata_addr = find_symbol("xmon_fw_idata", sym_data | sym_bss,NULL);
		g_xmon_kick_addr = find_symbol("xmon_fw_kick", sym_data | sym_bss,NULL);
		rem_writel(virt_to_phys(g_xmon_iflags_addr), XMON_FW_FLAGS_IN_ATTACHED);
	}
	restore_console();

	update_remote_data(1);
}

static void
catch_cpu(void)
{
#define KEYLARGO_GPIO_EXTINT_0		0x58
#define KL_GPIO_RESET_CPU0		(KEYLARGO_GPIO_EXTINT_0+0x03)
#define KL_GPIO_RESET_CPU1		(KEYLARGO_GPIO_EXTINT_0+0x04)
#define KL_GPIO_RESET_CPU2		(KEYLARGO_GPIO_EXTINT_0+0x0f)
#define KL_GPIO_RESET_CPU3		(KEYLARGO_GPIO_EXTINT_0+0x10)
#define KL_BASE				0x80000000UL // FIXME
	int cpu_no;
	unsigned long ioaddr;
	unsigned long ioshift;
	unsigned long iomask;
	unsigned long iodata;
	
#if 0
	const int reset_lines[] = {	KL_GPIO_RESET_CPU0,
					KL_GPIO_RESET_CPU1,
					KL_GPIO_RESET_CPU2,
					KL_GPIO_RESET_CPU3 };
	
#endif
	const int reset_lines[] = {	0x71, 0x72, 0x73, 0x74 };
	if (!g_target_ok)
		return;
	need_console();
	printf("(PMac only !) CPU number (0..3) : ");
	scanf("%d", &cpu_no);
	if (cpu_no < 0 || cpu_no > 3) {
		printf("CPU number out of bounds !\n");
		return;
	}
	ioaddr = KL_BASE + reset_lines[cpu_no];
	ioshift = (ioaddr & 0x3) << 3;
	ioaddr &= ~0x3;
	iomask = ~(0xff000000 >> ioshift);
	iodata = rem_readl(ioaddr);
	iodata &= iomask;
	rem_writel(ioaddr, iodata | (0x04000000 >> ioshift));
	usleep(10);
	rem_writel(ioaddr, iodata | (0x00000000 >> ioshift));
	restore_console();
}

static void
break_xmon(void)
{
	rem_writel(virt_to_phys(g_xmon_kick_addr), 1);
}

static int
menu_dispatch(char key)
{
	switch(key) {
		case 0x11: /* ctrl-Q */
			return 1;
		case 0x14: /* ctrl-T */
			select_target(-1);
			break;
		case 0x12: /* ctrl-R */
			read_quadlet();
			break;
		case 0x15: /* ctrl-U */
			auto_update = !auto_update;
			if (auto_update)
				printf("Auto update mode. Press Ctrl-u again to disable\n\r");
			else
				printf("Auto update modus disabled\n\r");
			update_dmesg();
			break;
		case 0x17: /* ctrl-W */
			write_quadlet();
			break;
		case 0x01: /* ctrl-A */
			attach_kernel();
			break;
		case 0x03: /* ctrl-C */
#ifndef __ppc__
			return 1;
#endif
			catch_cpu();
			break;
		case 0x04: /* ctrl-D */
			display_dmesg();
			break;
		case 0x08: /* ctrl-H */
			menu_show();
			break;
	        case 0x0f: /* ctrl-O */
			break_xmon();
			break;
		default:
			if (g_attached)
				send_xmon_key(key);
	}
	return 0;
}

void usage(void)
{
	fprintf(stderr, 
		"firescope [-u] [-aTARGETNUMBER] [-wLOGFILE] [-A]\n"
		"-u go into auto update mode\n"		
		"-aTARGETNUM attach to target number\n"
		"-wLOGFILE write all output from target into logfile\n"
		"-t Don't change tty mode. Must specify -a or -A. Implies -u\n"
		"-A attach to first non local target\n");	
		
	exit(1);
}

int
main(int argc, char** argv)
{
	int attach_to = -1;
	int fd, rc;
	int opt;
	while ((opt = getopt(argc,argv,"a:uAw:t")) != -1) { 
		switch (opt) { 
		case 'u': 
			auto_update = 1;
			break;
		case 'a': 
			attach_to = atoi(optarg);
			break;
		case 'A':
			attach_to = -2;
			break;
		case 'w': 
			logfile = fopen(optarg,"w+");
			if (!logfile) 
				perror(optarg), exit(1);
			break;
		case 't':
			auto_update = 1;
			cookedtty = 1;
			break;
		default:
			usage();
		}
	}
	if (cookedtty && attach_to == -1)
		usage();

	if (setup_handle(0) != 0)
		return 0;
	fd = raw1394_get_fd(g_handle);

	if (optind < argc) {
		int smfd;
		int nread;
		int allocd = 0;

		smfd = open(argv[optind], O_RDONLY);
		if (smfd < 0) {
			printf("Can't load system.map <%s>\n", argv[optind]);
			exit(1);
		}

		do {
			if (g_sysmap_size == allocd) {
				/* Don't use stat because that doesn't work on /proc/kallsyms */
				allocd += 4096;
				g_sysmap = realloc(g_sysmap, allocd);
				if (g_sysmap == NULL) {
					printf("Out of memory reading system.map <%s>\n", argv[optind]);
					exit(1);
				}
			}

			nread = read(smfd, &g_sysmap[g_sysmap_size], allocd - g_sysmap_size);
			if (nread == -1) {
				printf("Error reading system.map <%s>\n", argv[optind]);
				exit(1);
			}
			g_sysmap_size += nread;
		} while (nread != 0);
		g_sysmap[g_sysmap_size] = '\0';
		printf("Loaded system.map <%s> <%u> bytes\n", argv[optind], g_sysmap_size);
	}
	if (!cookedtty) { 
		tcgetattr(STDIN_FILENO, &g_norm_tio);
		memcpy(&g_raw_tio, &g_norm_tio, sizeof(struct termios));
		cfmakeraw(&g_raw_tio);
//		g_raw_tio.c_oflag |= OCRNL;
//		g_raw_tio.c_lflag &= ~ICANON;
		restore_console();
	}

	if (!auto_update && !cookedtty)
		menu_show();
	if (attach_to != -1) { 
		select_target(attach_to);
		attach_kernel();
	}
	if (cookedtty) 
		display_dmesg();
	if (auto_update)
		update_dmesg();
	do {
		struct pollfd pfds[2];
		char key = 0;
		int loop = 0;

		memset(&pfds, 0, sizeof(pfds));
		pfds[1].fd = STDIN_FILENO;
		pfds[1].events = POLLIN;
		pfds[0].fd = fd;
		pfds[0].events = POLLIN|POLLPRI|POLLERR|POLLHUP;

		int timeout = -1;
		if (auto_update || g_attached) 
			timeout = 10;
		if (logfile)
			fflush(logfile);

		rc = poll(pfds, 2, timeout);
		if (rc < 0) {
			rc = errno;
			if (rc != EINTR) {
				printf("poll error %d, exiting...\n", rc);
				goto bail;
			}
		} else if (rc > 0) {
			if (pfds[1].revents != 0)
				read(STDIN_FILENO, &key, 1);
			if (pfds[0].revents != 0)
				loop = 1;
		}
		if (auto_update)
			update_dmesg();
		if (g_attached)
			update_remote_data(0);
		if (loop)
			raw1394_loop_iterate(g_handle);
		if (key && menu_dispatch(key) != 0)
			goto bail;
		if (g_change_occurred) {
			g_change_occurred = 0;
			if (!auto_update)
				menu_show();
		}
	} while(1);	

bail:
	if (!cookedtty)
		tcsetattr(STDIN_FILENO, TCSAFLUSH, &g_norm_tio);
	printf("Exiting...\n");
	raw1394_destroy_handle(g_handle);
	return 0;
}
