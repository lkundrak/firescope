#ifndef __FIRESCOPE_H__
#define __FIRESCOPE_H__

#define CSR_BASE	0xfffff0000000ULL
#define NR_CPUS		32

enum {
	sym_bad  = 0,
	sym_text = 0x00000001,
	sym_data = 0x00000002,
	sym_bss  = 0x00000004
};

extern raw1394handle_t		g_handle;
extern nodeid_t			g_target;
extern int			g_target_ok;
extern u_int64_t		g_target_uid;
extern int			g_change_occurred;
extern int verbose,rem_ptrsize;

static void rem_writel(nodeaddr_t addr, unsigned long data)
{
	int rc;
	
	if (!g_target_ok)
		return;
	if (addr & 0x3) {
		printf("unaligned rem_writel(%lx, %lx)\n", (long)addr, data);
		return;
	}
	rc = raw1394_write(g_handle, g_target, addr, 4, (quadlet_t *)&data);
	if (rc < 0)
		printf("remote write failed, addr=%lx, data=%lx", (long)addr, data);
}

static unsigned long rem_readl(nodeaddr_t addr)
{
	quadlet_t data = 0xffffffff;
	int rc;
	
	if (!g_target_ok)
		return data;
	if (addr & 0x3) {
		printf("unaligned rem_readl(%lx)\n", addr);
		return data;
	}
	rc = raw1394_read(g_handle, g_target, addr, 4, &data);
	if (rc < 0)
		printf("remote read failed, addr=%lx", addr);
	if (verbose)
		printf("readl addr %lx -> %x\n", addr, data);
	return data;
}


static unsigned long rem_readq(nodeaddr_t addr)
{
	long long data = -1LL;
	int rc;
	
	if (!g_target_ok)
		return data;
	if (addr & 0x3) {
		printf("unaligned rem_readq(%lx)\n", addr);
		return data;
	}
	rc = raw1394_read(g_handle, g_target, addr, 8, (quadlet_t *)&data);
	if (rc < 0)
		printf("remote read failed, addr=%lx", addr);
	return data;
}

static inline unsigned long rem_readptr(nodeaddr_t addr)
{
	if (rem_ptrsize == 8) 
		return rem_readq(addr);
	return rem_readl(addr);
}

/* Todo: deal with unaligned data */
static int rem_readblk(void* dest, nodeaddr_t addr, size_t size)
{
	quadlet_t data;
	unsigned int* cdst = (unsigned int*)dest;

	if (!g_target_ok)
		return -1;
	while(size) {
		data = rem_readl(addr);
		if (data == 0xffffffff)
			return -1;
		*(cdst++) = data;
		addr += 4;
		size = (size < 4)  ? 0 : (size - 4);
	}
	return 0;
}

#if 0
static inline unsigned long phys_to_virt(nodeaddr_t phys_addr)
{
	return (phys_addr + KERNELBASE);
}
#endif

static inline nodeaddr_t virt_to_phys(unsigned long long virt_addr)
{
	if (rem_ptrsize == 8)  {
		//printf("rem_ptr_size=8 virt=%llx\n", virt_addr);
		unsigned long long ret = ((virt_addr >= 0xffffffff80000000ULL) ? 
			(virt_addr - 0xffffffff80000000ULL) : (virt_addr - 0xffff810000000000ULL));

		// Quick hack: We read the virtual address of the printk buffer over firewire,
		// but on firescope-i386 -> x86_64-host we only seem the copy the low 32bit.
		//
		// This is a dirty hack to get it working between x86_64 and i386 and it works
		// for x86_64->x86_64, x86_64->i386 as well as i386->x86_64, i386->i386:
		if (ret >= 0x80000000UL)
			ret = virt_addr - 0x80000000UL;

		//printf("phys=%lx\n", ret);
		
		return ret;
	}
	else
		return (nodeaddr_t)(virt_addr - 0xc0000000);
}

#endif /* __FIRESCOPE_H__ */

