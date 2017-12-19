/*
 * Copyright 2018 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM	ftw

#if !defined(_FTW_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)

#define _FTW_TRACE_H
#include <linux/tracepoint.h>
#include <linux/sched.h>

TRACE_EVENT(	ftw_open_event,

		TP_PROTO(struct task_struct *tsk,
			 int instid),

		TP_ARGS(tsk, instid),

		TP_STRUCT__entry(
			__field(struct task_struct *, tsk)
			__field(int, instid)
			__field(int, pid)
		),

		TP_fast_assign(
			__entry->pid = tsk->pid;
			__entry->instid = instid;
		),

		TP_printk("pid=%d, inst=%d", __entry->pid, __entry->instid)
);

TRACE_EVENT(	ftw_mmap_event,

		TP_PROTO(struct task_struct *tsk,
			 int instid,
			 unsigned long paste_addr,
			 unsigned long vma_start),

		TP_ARGS(tsk, instid, paste_addr, vma_start),

		TP_STRUCT__entry(
			__field(struct task_struct *, tsk)
			__field(int, pid)
			__field(int, instid)
			__field(unsigned long, paste_addr)
			__field(unsigned long, vma_start)
		),

		TP_fast_assign(
			__entry->pid = tsk->pid;
			__entry->instid = instid;
			__entry->paste_addr = paste_addr;
			__entry->vma_start = vma_start;
		),

		TP_printk(
			"pid=%d, inst=%d, pasteaddr=0x%16lx, vma_start=0x%16lx",
			__entry->pid, __entry->instid, __entry->paste_addr,
			__entry->vma_start)
);

#endif /* _FTW_TRACE_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE ftw-trace
#include <trace/define_trace.h>
