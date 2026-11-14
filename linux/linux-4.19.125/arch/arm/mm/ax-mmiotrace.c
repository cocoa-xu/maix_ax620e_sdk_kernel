// SPDX-License-Identifier: GPL-2.0
/*
 * Register access tracing for drivers that map registers through AX_OSAL.
 *
 * Every such mapping gets a second, "fake" virtual range backed by the same
 * physical pages, and the driver is handed the fake range. While a range is
 * armed its PTEs are cleared, so each access aborts: the abort handler
 * decodes the load or store, performs it through the real mapping, logs it
 * and steps over the instruction. Disarmed ranges are plain mappings.
 *
 * Control and output live in /proc/ax_mmiotrace/{control,trace,regions}.
 */

#include <linux/bitops.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/sched/clock.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include <asm/ax-mmiotrace.h>
#include <asm/cacheflush.h>
#include <asm/mach/map.h>
#include <asm/opcodes.h>
#include <asm/pgtable.h>
#include <asm/ptrace.h>
#include <asm/tlbflush.h>

#include "mm.h"

#define AXMT_MAX_REGIONS	256
#define AXMT_DRAM_BASE		0x40000000UL
#define AXMT_MAX_MARKS		64
#define AXMT_MARK_LEN		48

enum axmt_op { AXMT_READ, AXMT_WRITE, AXMT_MAP, AXMT_UNMAP, AXMT_UNDECODED, AXMT_MARK };

struct axmt_region {
	unsigned long fake;
	unsigned long real;
	phys_addr_t phys;
	size_t size;
	unsigned int mtype;
	bool used;
	bool armed;
	pte_t *saved;
	struct vm_struct *area;
	char owner[MODULE_NAME_LEN];
};

struct axmt_rec {
	u64 ts;
	u32 phys;
	u32 val;
	u32 val_hi;
	u32 pc;
	u16 region;
	u8 op;
	u8 width;
	u8 cpu;
	u8 pad[3];
};

struct axmt_insn {
	u8 len;
	u8 load;
	u8 width;
	u8 sign;
	u8 rt;
	u8 rt2;
	u8 rn;
	s8 dir;
	u16 reglist;
	bool wb;
	unsigned long wb_val;
	unsigned long ea;
};

static struct axmt_region regions[AXMT_MAX_REGIONS];
static DEFINE_RAW_SPINLOCK(regions_lock);
static DEFINE_PER_CPU(int, axmt_busy);
static unsigned long bound_lo = ULONG_MAX;
static unsigned long bound_hi;
static int armed_regions;

static struct axmt_rec *ring;
static unsigned int ring_cap = CONFIG_AX_MMIOTRACE_RECORDS;
static unsigned int ring_len;
static unsigned int dropped;
static DEFINE_RAW_SPINLOCK(ring_lock);

static DEFINE_MUTEX(ctl_lock);
static bool tracing;
static char filter[256] = CONFIG_AX_MMIOTRACE_FILTER;
static char marks[AXMT_MAX_MARKS][AXMT_MARK_LEN];
static unsigned int nmarks;

static void axmt_log(u8 op, u16 region, u32 phys, u8 width, u32 val, u32 val_hi, u32 pc)
{
	struct axmt_rec *rec;
	unsigned long flags;

	raw_spin_lock_irqsave(&ring_lock, flags);
	if (!ring || ring_len >= ring_cap) {
		if (ring)
			dropped++;
		raw_spin_unlock_irqrestore(&ring_lock, flags);
		return;
	}
	rec = &ring[ring_len++];
	rec->ts = local_clock();
	rec->phys = phys;
	rec->val = val;
	rec->val_hi = val_hi;
	rec->pc = pc;
	rec->region = region;
	rec->op = op;
	rec->width = width;
	rec->cpu = raw_smp_processor_id();
	raw_spin_unlock_irqrestore(&ring_lock, flags);
}

static pte_t *axmt_pte(unsigned long va)
{
	pmd_t *pmd = pmd_offset(pud_offset(pgd_offset_k(va), va), va);

	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;
	return pte_offset_kernel(pmd, va);
}

/*
 * Runs in the abort handler with IRQs off. On Cortex-A7/A53 the kernel TLB
 * flush is broadcast in hardware; a CPU that needs IPIs for it cannot use this.
 */
static void axmt_set_armed(struct axmt_region *r, bool arm)
{
	unsigned long va;
	unsigned int i = 0;

	if (r->armed == arm)
		return;
	for (va = r->fake; va < r->fake + r->size; va += PAGE_SIZE, i++) {
		pte_t *ptep = axmt_pte(va);

		if (ptep)
			set_pte_ext(ptep, arm ? __pte(0) : r->saved[i], 0);
	}
	flush_tlb_kernel_range(r->fake, r->fake + r->size);
	r->armed = arm;
	armed_regions += arm ? 1 : -1;
}

static bool axmt_owner_matches(const char *owner)
{
	const char *p = filter;
	size_t n = strlen(owner);

	while (*p) {
		const char *end = strchrnul(p, ',');

		if ((end - p == 1 && *p == '*') || (end - p == n && !strncmp(p, owner, n)))
			return true;
		p = *end ? end + 1 : end;
	}
	return false;
}

void __iomem *ax_mmiotrace_map(phys_addr_t phys, size_t size, void __iomem *real,
			       enum ax_mmiotrace_type type, unsigned long caller)
{
	unsigned long offset = phys & ~PAGE_MASK;
	phys_addr_t pphys = phys - offset;
	size_t psize = PAGE_ALIGN(size + offset);
	unsigned int mtype = type == AX_MMIOTRACE_DEVICE_WC ? MT_DEVICE_WC : MT_DEVICE;
	char owner[MODULE_NAME_LEN] = "vmlinux";
	struct axmt_region *r = NULL;
	struct vm_struct *area;
	unsigned long va, flags;
	struct module *mod;
	pte_t *saved;
	int i, idx = -1;

	if (!real || !size || phys >= AXMT_DRAM_BASE)
		return real;

	preempt_disable();
	mod = __module_address(caller);
	if (mod)
		strlcpy(owner, mod->name, sizeof(owner));
	preempt_enable();

	mutex_lock(&ctl_lock);
	if (!axmt_owner_matches(owner))
		goto out;

	area = get_vm_area_caller(psize, VM_IOREMAP, (void *)caller);
	if (!area)
		goto out;
	area->phys_addr = pphys;
	va = (unsigned long)area->addr;
	if (ioremap_page_range(va, va + psize, pphys, __pgprot(get_mem_type(mtype)->prot_pte))) {
		free_vm_area(area);
		goto out;
	}
	flush_cache_vmap(va, va + psize);

	saved = kcalloc(psize >> PAGE_SHIFT, sizeof(*saved), GFP_KERNEL);
	if (!saved) {
		free_vm_area(area);
		goto out;
	}
	for (i = 0; va < (unsigned long)area->addr + psize; va += PAGE_SIZE, i++) {
		pte_t *ptep = axmt_pte(va);

		saved[i] = ptep ? *ptep : __pte(0);
	}

	raw_spin_lock_irqsave(&regions_lock, flags);
	for (i = 0; i < AXMT_MAX_REGIONS; i++) {
		if (!regions[i].used) {
			idx = i;
			break;
		}
	}
	if (idx >= 0) {
		r = &regions[idx];
		r->fake = (unsigned long)area->addr;
		r->real = (unsigned long)real - offset;
		r->phys = pphys;
		r->size = psize;
		r->mtype = mtype;
		r->saved = saved;
		r->area = area;
		r->armed = false;
		r->used = true;
		strlcpy(r->owner, owner, sizeof(r->owner));
		bound_lo = min(bound_lo, r->fake);
		bound_hi = max(bound_hi, r->fake + psize);
		if (tracing)
			axmt_set_armed(r, true);
	}
	raw_spin_unlock_irqrestore(&regions_lock, flags);

	if (!r) {
		kfree(saved);
		free_vm_area(area);
		goto out;
	}
	axmt_log(AXMT_MAP, idx, pphys, 0, psize, r->fake, caller);
	mutex_unlock(&ctl_lock);
	return (void __iomem *)(r->fake + offset);
out:
	mutex_unlock(&ctl_lock);
	return real;
}

bool ax_mmiotrace_unmap(volatile void __iomem *addr)
{
	unsigned long a = (unsigned long)addr, flags;
	struct axmt_region r;
	int i, idx = -1;

	if (a < READ_ONCE(bound_lo) || a >= READ_ONCE(bound_hi))
		return false;

	raw_spin_lock_irqsave(&regions_lock, flags);
	for (i = 0; i < AXMT_MAX_REGIONS; i++) {
		if (regions[i].used && a >= regions[i].fake &&
		    a < regions[i].fake + regions[i].size) {
			idx = i;
			break;
		}
	}
	if (idx >= 0) {
		axmt_set_armed(&regions[idx], false);
		r = regions[idx];
		regions[idx].used = false;
	}
	raw_spin_unlock_irqrestore(&regions_lock, flags);
	if (idx < 0)
		return false;

	axmt_log(AXMT_UNMAP, idx, r.phys, 0, r.size, r.fake, _RET_IP_);
	free_vm_area(r.area);
	kfree(r.saved);
	iounmap((void __iomem *)r.real);
	return true;
}

static unsigned long axmt_it_advance(unsigned long cpsr)
{
	if ((cpsr & 0x06000400) == 0) {
		cpsr &= ~PSR_IT_MASK;
	} else {
		const unsigned long mask = 0x06001c00;
		unsigned long it = cpsr & mask;

		it <<= 1;
		it |= it >> (27 - 10);
		it &= mask;
		cpsr &= ~mask;
		cpsr |= it;
	}
	return cpsr;
}

static bool axmt_decode_t16(u16 hw, struct axmt_insn *in)
{
	static const u8 reg_width[8] = { 4, 2, 1, 1, 4, 2, 1, 2 };
	static const u8 reg_load[8] = { 0, 0, 0, 1, 1, 1, 1, 1 };
	static const u8 reg_sign[8] = { 0, 0, 0, 1, 0, 0, 0, 1 };
	int opb = (hw >> 9) & 7;

	in->len = 2;
	switch (hw >> 12) {
	case 0x5:
		in->width = reg_width[opb];
		in->load = reg_load[opb];
		in->sign = reg_sign[opb];
		in->rt = hw & 7;
		return true;
	case 0x6:
	case 0x7:
	case 0x8:
		in->width = (hw >> 12) == 0x6 ? 4 : (hw >> 12) == 0x7 ? 1 : 2;
		in->load = (hw >> 11) & 1;
		in->rt = hw & 7;
		return true;
	case 0xc:
		in->load = (hw >> 11) & 1;
		in->rn = (hw >> 8) & 7;
		in->reglist = hw & 0xff;
		in->width = 4;
		in->dir = 1;
		in->wb = !in->load || !(in->reglist & BIT(in->rn));
		return in->reglist != 0;
	}
	return false;
}

static bool axmt_decode_t32(u16 hw1, u16 hw2, struct axmt_insn *in, struct pt_regs *regs)
{
	in->len = 4;

	if ((hw1 & 0xfe00) == 0xf800) {
		int sign = (hw1 >> 8) & 1, imm12 = (hw1 >> 7) & 1, size = (hw1 >> 5) & 3;

		in->load = (hw1 >> 4) & 1;
		in->rn = hw1 & 0xf;
		in->rt = hw2 >> 12;
		if (size == 3 || in->rn == 15 || (sign && !in->load) || (in->load && in->rt == 15))
			return false;
		in->width = 1 << size;
		in->sign = sign;
		if (!imm12 && (hw2 & 0x0800)) {
			int p = (hw2 >> 10) & 1, u = (hw2 >> 9) & 1, w = (hw2 >> 8) & 1;
			unsigned long base = regs->uregs[in->rn], off = hw2 & 0xff;

			if (!p && !w)
				return false;
			in->wb = w;
			in->wb_val = u ? base + off : base - off;
		} else if (!imm12 && (hw2 & 0x0fc0)) {
			return false;
		}
		return true;
	}

	if ((hw1 & 0xfe40) == 0xe840 && (hw1 & 0x0120)) {
		int p = (hw1 >> 8) & 1, u = (hw1 >> 7) & 1;
		unsigned long base, off, offaddr;

		in->load = (hw1 >> 4) & 1;
		in->rn = hw1 & 0xf;
		in->rt = hw2 >> 12;
		in->rt2 = (hw2 >> 8) & 0xf;
		in->width = 8;
		if (in->rn == 15)
			return false;
		base = regs->uregs[in->rn];
		off = (hw2 & 0xff) << 2;
		offaddr = u ? base + off : base - off;
		in->ea = p ? offaddr : base;
		in->wb = (hw1 >> 5) & 1;
		in->wb_val = offaddr;
		return true;
	}

	if ((hw1 & 0xfe40) == 0xe800) {
		int op = (hw1 >> 7) & 3;

		if (op != 1 && op != 2)
			return false;
		in->load = (hw1 >> 4) & 1;
		in->rn = hw1 & 0xf;
		in->reglist = hw2;
		in->width = 4;
		in->dir = op == 1 ? 1 : -1;
		in->wb = (hw1 >> 5) & 1;
		return in->rn != 15 && in->reglist && !(in->reglist & BIT(15));
	}
	return false;
}

static u32 axmt_read(void __iomem *p, unsigned int width)
{
	switch (width) {
	case 1:
		return __raw_readb(p);
	case 2:
		return __raw_readw(p);
	default:
		return __raw_readl(p);
	}
}

static void axmt_write(void __iomem *p, u32 v, unsigned int width)
{
	switch (width) {
	case 1:
		__raw_writeb(v, p);
		break;
	case 2:
		__raw_writew(v, p);
		break;
	default:
		__raw_writel(v, p);
	}
}

static bool axmt_do_single(struct axmt_region *r, int idx, unsigned long ea,
			   struct axmt_insn *in, struct pt_regs *regs)
{
	unsigned int bytes = in->width;
	void __iomem *p;
	u32 v, v2 = 0;

	if (ea < r->fake || ea + bytes > r->fake + r->size)
		return false;
	p = (void __iomem *)(r->real + (ea - r->fake));

	if (in->load) {
		if (bytes == 8) {
			v = __raw_readl(p);
			v2 = __raw_readl(p + 4);
			regs->uregs[in->rt] = v;
			regs->uregs[in->rt2] = v2;
		} else {
			v = axmt_read(p, bytes);
			if (in->sign)
				regs->uregs[in->rt] = bytes == 1 ? (u32)(s32)(s8)v : (u32)(s32)(s16)v;
			else
				regs->uregs[in->rt] = v;
		}
	} else {
		v = regs->uregs[in->rt];
		if (bytes == 8) {
			v2 = regs->uregs[in->rt2];
			__raw_writel(v, p);
			__raw_writel(v2, p + 4);
		} else {
			if (bytes < 4)
				v &= (1U << (8 * bytes)) - 1;
			axmt_write(p, v, bytes);
		}
	}
	axmt_log(in->load ? AXMT_READ : AXMT_WRITE, idx, r->phys + (ea - r->fake), bytes,
		 v, v2, regs->ARM_pc);
	return true;
}

static bool axmt_do_multi(struct axmt_region *r, int idx, struct axmt_insn *in,
			  struct pt_regs *regs)
{
	unsigned int n = hweight16(in->reglist), i, k = 0;
	unsigned long base = regs->uregs[in->rn];
	unsigned long start = in->dir > 0 ? base : base - 4 * n;

	if (start < r->fake || start + 4 * n > r->fake + r->size)
		return false;
	for (i = 0; i < 15; i++) {
		unsigned long off = start + 4 * k - r->fake;
		void __iomem *p = (void __iomem *)(r->real + off);
		u32 v;

		if (!(in->reglist & BIT(i)))
			continue;
		if (in->load) {
			v = __raw_readl(p);
			regs->uregs[i] = v;
		} else {
			v = regs->uregs[i];
			__raw_writel(v, p);
		}
		axmt_log(in->load ? AXMT_READ : AXMT_WRITE, idx, r->phys + off, 4, v, 0,
			 regs->ARM_pc);
		k++;
	}
	in->wb_val = in->dir > 0 ? base + 4 * n : base - 4 * n;
	return true;
}

static bool axmt_emulate(struct axmt_region *r, int idx, unsigned long far, struct pt_regs *regs)
{
	struct axmt_insn in = { 0 };
	unsigned long pc = regs->ARM_pc;
	u16 hw1 = 0, hw2 = 0;
	bool ok = false;

	if (thumb_mode(regs) && !probe_kernel_read(&hw1, (void *)pc, 2)) {
		hw1 = __mem_to_opcode_thumb16(hw1);
		if ((hw1 >> 11) >= 0x1d) {
			if (!probe_kernel_read(&hw2, (void *)(pc + 2), 2)) {
				hw2 = __mem_to_opcode_thumb16(hw2);
				ok = axmt_decode_t32(hw1, hw2, &in, regs);
			}
		} else {
			ok = axmt_decode_t16(hw1, &in);
		}
	}
	if (ok) {
		if (in.reglist)
			ok = axmt_do_multi(r, idx, &in, regs);
		else
			ok = axmt_do_single(r, idx, in.width == 8 ? in.ea : far, &in, regs);
	}
	if (!ok) {
		axmt_log(AXMT_UNDECODED, idx, r->phys + (far - r->fake), in.len,
			 hw1 | (u32)hw2 << 16, thumb_mode(regs), pc);
		return false;
	}
	if (in.wb)
		regs->uregs[in.rn] = in.wb_val;
	regs->ARM_pc += in.len;
	regs->ARM_cpsr = axmt_it_advance(regs->ARM_cpsr);
	return true;
}

static int axmt_find_armed(unsigned long addr)
{
	int i;

	for (i = 0; i < AXMT_MAX_REGIONS; i++) {
		unsigned long fake = READ_ONCE(regions[i].fake);

		if (READ_ONCE(regions[i].used) && READ_ONCE(regions[i].armed) &&
		    addr >= fake && addr < fake + READ_ONCE(regions[i].size))
			return i;
	}
	return -1;
}

bool ax_mmiotrace_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	unsigned long flags;
	int i;

	if (!READ_ONCE(armed_regions) || user_mode(regs) ||
	    addr < READ_ONCE(bound_lo) || addr >= READ_ONCE(bound_hi))
		return false;

	/*
	 * Emulation touches the real mapping and the trace buffer, both vmalloc
	 * addresses that may need a lazy page-table sync. That nested abort must
	 * go to the normal handler: this CPU already holds regions_lock.
	 */
	local_irq_save(flags);
	if (__this_cpu_read(axmt_busy) || axmt_find_armed(addr) < 0) {
		local_irq_restore(flags);
		return false;
	}
	__this_cpu_write(axmt_busy, 1);
	raw_spin_lock(&regions_lock);
	i = axmt_find_armed(addr);
	if (i >= 0 && !axmt_emulate(&regions[i], i, addr, regs))
		axmt_set_armed(&regions[i], false);
	raw_spin_unlock(&regions_lock);
	__this_cpu_write(axmt_busy, 0);
	local_irq_restore(flags);
	return i >= 0;
}

static void axmt_arm_all(bool arm)
{
	unsigned long flags;
	int i;

	raw_spin_lock_irqsave(&regions_lock, flags);
	for (i = 0; i < AXMT_MAX_REGIONS; i++)
		if (regions[i].used)
			axmt_set_armed(&regions[i], arm);
	raw_spin_unlock_irqrestore(&regions_lock, flags);
}

static int axmt_start(void)
{
	if (!ring) {
		struct axmt_rec *buf = vzalloc(array_size(ring_cap, sizeof(*buf)));

		if (!buf)
			return -ENOMEM;
		raw_spin_lock_irq(&ring_lock);
		ring = buf;
		raw_spin_unlock_irq(&ring_lock);
	}
	tracing = true;
	axmt_arm_all(true);
	return 0;
}

static void axmt_stop(void)
{
	tracing = false;
	axmt_arm_all(false);
}

static ssize_t axmt_control_write(struct file *file, const char __user *ubuf,
				  size_t count, loff_t *ppos)
{
	char buf[300], *cmd, *arg;
	int ret = 0;

	if (count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	cmd = strim(buf);
	arg = strchr(cmd, ' ');
	if (arg)
		*arg++ = '\0';

	mutex_lock(&ctl_lock);
	if (!strcmp(cmd, "on")) {
		ret = axmt_start();
	} else if (!strcmp(cmd, "off")) {
		axmt_stop();
	} else if (!strcmp(cmd, "clear")) {
		raw_spin_lock_irq(&ring_lock);
		ring_len = 0;
		dropped = 0;
		nmarks = 0;
		raw_spin_unlock_irq(&ring_lock);
	} else if (!strcmp(cmd, "filter") && arg) {
		strlcpy(filter, strim(arg), sizeof(filter));
	} else if (!strcmp(cmd, "mark") && arg) {
		if (nmarks < AXMT_MAX_MARKS) {
			strlcpy(marks[nmarks], strim(arg), AXMT_MARK_LEN);
			axmt_log(AXMT_MARK, 0, 0, 0, nmarks++, 0, 0);
		} else {
			ret = -ENOSPC;
		}
	} else if (!strcmp(cmd, "size") && arg && !tracing) {
		unsigned int n;

		ret = kstrtouint(arg, 0, &n);
		if (!ret && n) {
			struct axmt_rec *old;

			raw_spin_lock_irq(&ring_lock);
			old = ring;
			ring = NULL;
			ring_len = 0;
			ring_cap = n;
			raw_spin_unlock_irq(&ring_lock);
			vfree(old);
		}
	} else {
		ret = -EINVAL;
	}
	mutex_unlock(&ctl_lock);
	return ret ? ret : count;
}

static int axmt_control_show(struct seq_file *m, void *v)
{
	seq_printf(m, "tracing %s\nrecords %u/%u\ndropped %u\nregions armed %d\nfilter %s\n",
		   tracing ? "on" : "off", ring_len, ring_cap, dropped, armed_regions, filter);
	seq_puts(m, "commands: on | off | clear | filter <mod,mod|*> | mark <text> | size <n>\n");
	return 0;
}

static int axmt_control_open(struct inode *inode, struct file *file)
{
	return single_open(file, axmt_control_show, NULL);
}

static const struct file_operations axmt_control_fops = {
	.open = axmt_control_open,
	.read = seq_read,
	.write = axmt_control_write,
	.llseek = seq_lseek,
	.release = single_release,
};

static void *axmt_trace_start(struct seq_file *m, loff_t *pos)
{
	return *pos < READ_ONCE(ring_len) ? pos : NULL;
}

static void *axmt_trace_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return axmt_trace_start(m, pos);
}

static void axmt_trace_stop(struct seq_file *m, void *v)
{
}

static int axmt_trace_show(struct seq_file *m, void *v)
{
	const struct axmt_rec *rec = &ring[*(loff_t *)v];
	u64 secs = rec->ts;
	unsigned long us = do_div(secs, NSEC_PER_SEC) / NSEC_PER_USEC;

	seq_printf(m, "%5llu.%06lu %u ", secs, us, rec->cpu);
	switch (rec->op) {
	case AXMT_READ:
	case AXMT_WRITE:
		seq_printf(m, "%c%u r%u %08x ", rec->op == AXMT_READ ? 'R' : 'W', rec->width,
			   rec->region, rec->phys);
		if (rec->width == 8)
			seq_printf(m, "%08x:%08x", rec->val_hi, rec->val);
		else
			seq_printf(m, "%08x", rec->val);
		seq_printf(m, " %pS\n", (void *)(unsigned long)rec->pc);
		break;
	case AXMT_MAP:
		seq_printf(m, "MAP r%u %08x size %x fake %08x by %pS\n", rec->region, rec->phys,
			   rec->val, rec->val_hi, (void *)(unsigned long)rec->pc);
		break;
	case AXMT_UNMAP:
		seq_printf(m, "UNMAP r%u %08x size %x fake %08x by %pS\n", rec->region, rec->phys,
			   rec->val, rec->val_hi, (void *)(unsigned long)rec->pc);
		break;
	case AXMT_UNDECODED:
		seq_printf(m, "UNDECODED r%u %08x insn %08x %s at %pS, region left untraced\n",
			   rec->region, rec->phys, rec->val, rec->val_hi ? "T32" : "A32",
			   (void *)(unsigned long)rec->pc);
		break;
	case AXMT_MARK:
		seq_printf(m, "MARK %s\n", rec->val < AXMT_MAX_MARKS ? marks[rec->val] : "?");
		break;
	}
	return 0;
}

static const struct seq_operations axmt_trace_sops = {
	.start = axmt_trace_start,
	.next = axmt_trace_next,
	.stop = axmt_trace_stop,
	.show = axmt_trace_show,
};

static int axmt_trace_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &axmt_trace_sops);
}

static const struct file_operations axmt_trace_fops = {
	.open = axmt_trace_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

static int axmt_regions_show(struct seq_file *m, void *v)
{
	unsigned long flags;
	int i;

	raw_spin_lock_irqsave(&regions_lock, flags);
	for (i = 0; i < AXMT_MAX_REGIONS; i++) {
		const struct axmt_region *r = &regions[i];

		if (r->used)
			seq_printf(m, "r%-3d %-16s phys %08llx size %6zx fake %08lx real %08lx %s %s\n",
				   i, r->owner, (unsigned long long)r->phys, r->size, r->fake,
				   r->real, r->mtype == MT_DEVICE_WC ? "wc " : "dev",
				   r->armed ? "armed" : "direct");
	}
	raw_spin_unlock_irqrestore(&regions_lock, flags);
	return 0;
}

static int axmt_regions_open(struct inode *inode, struct file *file)
{
	return single_open(file, axmt_regions_show, NULL);
}

static const struct file_operations axmt_regions_fops = {
	.open = axmt_regions_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static int __init axmt_init(void)
{
	struct proc_dir_entry *dir = proc_mkdir("ax_mmiotrace", NULL);

	if (!dir)
		return -ENOMEM;
	proc_create("control", 0600, dir, &axmt_control_fops);
	proc_create("trace", 0400, dir, &axmt_trace_fops);
	proc_create("regions", 0400, dir, &axmt_regions_fops);

	if (IS_ENABLED(CONFIG_AX_MMIOTRACE_ARM_AT_BOOT)) {
		mutex_lock(&ctl_lock);
		axmt_start();
		mutex_unlock(&ctl_lock);
	}
	return 0;
}
late_initcall(axmt_init);
