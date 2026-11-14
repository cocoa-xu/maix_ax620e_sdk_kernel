/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_ARM_AX_MMIOTRACE_H
#define __ASM_ARM_AX_MMIOTRACE_H

#include <linux/types.h>

struct pt_regs;

enum ax_mmiotrace_type {
	AX_MMIOTRACE_DEVICE,
	AX_MMIOTRACE_DEVICE_WC,
};

#ifdef CONFIG_AX_MMIOTRACE
/**
 * ax_mmiotrace_map() - interpose a traceable range on a register mapping
 * @phys: physical address that was mapped
 * @size: size of the mapping
 * @real: address returned by ioremap()/ioremap_wc()
 * @type: memory type @real was mapped with
 * @caller: return address of the mapping helper, used to name the owner
 *
 * Return: the address to hand to the driver; @real if not interposed.
 */
void __iomem *ax_mmiotrace_map(phys_addr_t phys, size_t size, void __iomem *real,
			       enum ax_mmiotrace_type type, unsigned long caller);
/**
 * ax_mmiotrace_unmap() - release an interposed range and its real mapping
 * @addr: address previously returned by ax_mmiotrace_map()
 *
 * Return: true if @addr was interposed and has been released.
 */
bool ax_mmiotrace_unmap(volatile void __iomem *addr);
/**
 * ax_mmiotrace_fault() - emulate and log an access to an armed range
 * @addr: faulting address
 * @fsr: fault status
 * @regs: register state of the aborting context
 *
 * Return: true if the abort was handled.
 */
bool ax_mmiotrace_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs);
#else
static inline void __iomem *ax_mmiotrace_map(phys_addr_t phys, size_t size, void __iomem *real,
					     enum ax_mmiotrace_type type, unsigned long caller)
{
	return real;
}

static inline bool ax_mmiotrace_unmap(volatile void __iomem *addr)
{
	return false;
}

static inline bool ax_mmiotrace_fault(unsigned long addr, unsigned int fsr, struct pt_regs *regs)
{
	return false;
}
#endif

#endif
