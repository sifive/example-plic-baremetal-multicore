/* Copyright 2018 SiFive, Inc */
/* SPDX-License-Identifier: Apache-2.0 */

/*
 * This example requires a design-arty bsp that has switches as inputs into the PLIC.
 * This hierarchy can be checked in the design.dts file.
 */

#include <stdio.h>
#include <stdlib.h>

/* These includes get created at build time, and are based on the contents
 * in the bsp folder.  They are useful since they allow us
 * to use auto generated symbols and base addresses which may change
 * based on the design.
 */
#include <metal/machine.h>
#include <metal/machine/platform.h>
#include <metal/machine/inline.h>
#include <metal/lock.h>

/*
 * This test demonstrates how to enable and handle a global interrupt that
 * is managed by the Platform Level Interrupt Controller (PLIC), and routed
 * into the CPU through the local external interrupt connection, which
 * has interrupt ID #11.
 *
 * At the CPU level, we configure CLINT vectored mode of operation, which
 * allows lower latency to handle any local interrupt into the CPU.
 */

/* Define to enable all harts with all available PLIC interrupts */
#define ENABLE_PLIC_ALL_HARTS                    FALSE

#if __riscv_xlen == 32
#define MCAUSE_INTR                         0x80000000UL
#define MCAUSE_CAUSE                        0x000003FFUL
#else
#define MCAUSE_INTR                         0x8000000000000000UL
#define MCAUSE_CAUSE                        0x00000000000003FFUL
#endif
#define MCAUSE_CODE(cause)                  (cause & MCAUSE_CAUSE)

#define TRUE                                1
#define FALSE                               0

/* Compile time options to determine which interrupt modules we have */
#define CLINT_PRESENT                           (METAL_MAX_CLINT_INTERRUPTS > 0)
#define CLIC_PRESENT                            (METAL_MAX_CLIC_INTERRUPTS > 0)
#define PLIC_PRESENT                            (METAL_MAX_PLIC_INTERRUPTS > 0)
#ifdef METAL_SIFIVE_UART0
#define UART_PRESENT                            TRUE
#endif

#define DISABLE                 0
#define ENABLE                  1
#define RTC_FREQ                32768

/* Interrupt Specific defines - used for mtvec.mode field, which is bit[0] for
 * designs with CLINT, or [1:0] for designs with a CLIC */
#define MTVEC_MODE_CLINT_DIRECT                 0x00
#define MTVEC_MODE_CLINT_VECTORED               0x01
#define MTVEC_MODE_CLIC_DIRECT                  0x02
#define MTVEC_MODE_CLIC_VECTORED                0x03

#if CLINT_PRESENT
#define CLINT_BASE_ADDR                         METAL_RISCV_CLINT0_MSIP_BASE
#define MSIP_BASE_ADDR                          (CLINT_BASE_ADDR + METAL_RISCV_CLINT0_MSIP_BASE)
#define MTIMECMP_BASE_ADDR                      (CLINT_BASE_ADDR + METAL_RISCV_CLINT0_MTIMECMP_BASE)
#define MTIME_BASE_ADDR                         (CLINT_BASE_ADDR + METAL_RISCV_CLINT0_MTIME)
#endif

#if CLIC_PRESENT
#define CLIC_BASE_ADDR                          METAL_SIFIVE_CLIC0_0_BASE_ADDRESS
#define MSIP_BASE_ADDR                          (CLIC_BASE_ADDR + METAL_SIFIVE_CLIC0_MSIP_BASE)
#define MTIMECMP_BASE_ADDR                      (CLIC_BASE_ADDR + METAL_SIFIVE_CLIC0_MTIMECMP_BASE)
#define MTIME_BASE_ADDR                         (CLIC_BASE_ADDR + METAL_SIFIVE_CLIC0_MTIME)
#endif

/* These offsets generated manually for internal PLIC offsets */
#define PLIC_HART_THRESHOLD_OFFSET              0x1000
#define PLIC_HARTx_OFFSET                       0x100
#define PLIC_REGWIDTH                           0x4

/* The PLIC enable groupings are based on a "context", as defined by the PLIC Spec:
 * https://github.com/riscv/riscv-plic-spec/blob/master/riscv-plic.adoc#memory-map
 * SiFive U-series standard multi-core designs contain hart0 as only having
 * one context, which is Machine mode, since it is an S-series core without MMU.
 * As such, hart1 and beyond enable S- and M-modes, so each hart has two contexts.
 * Here, we define the hart1 base address as the starting point for *each* hart
 * containing two contexts.
 */
#define PLIC_HART0_ENABLE_BASE_ADDR             0x0
#define PLIC_HART1_ENABLE_BASE_ADDR             0x80

/* Check bsp/metal-platform.h for defined base addresses for your design */
#define PLIC_BASE_ADDR                          METAL_RISCV_PLIC0_0_BASE_ADDRESS
#define PLIC_PRIORITY_ADDR(plic_int)            (PLIC_BASE_ADDR + METAL_RISCV_PLIC0_PRIORITY_BASE + (PLIC_REGWIDTH * plic_int))
#define PLIC_PENDING_BASE_ADDR                  (PLIC_BASE_ADDR + METAL_RISCV_PLIC0_PENDING_BASE)
#define PLIC_ENABLE_BASE_ADDR                   (PLIC_BASE_ADDR + METAL_RISCV_PLIC0_ENABLE_BASE)
#define PLIC_ENABLE_SUPERVISOR_BASE_ADDR        (PLIC_BASE_ADDR + METAL_RISCV_PLIC0_ENABLE_BASE + PLIC_HARTx_OFFSET)
#define PLIC_THRESHOLD_ADDR(mhartid)            (PLIC_BASE_ADDR + METAL_RISCV_PLIC0_THRESHOLD + (mhartid * PLIC_HART_THRESHOLD_OFFSET))
#define PLIC_CLAIM_COMPLETE_ADDR(mhartid)       (PLIC_BASE_ADDR + METAL_RISCV_PLIC0_CLAIM + (mhartid * PLIC_HARTx_OFFSET))

/* different interrupt types for enables */
#define MACHINE_INTS                            0x31
#define SUPERVISOR_INTS                         0x51

/* prototypes */
void plic_sw_handler(uint32_t plic_id);
void plic_enable_disable(uint32_t int_id, uint32_t en_dis, uint32_t hartid, uint32_t m_or_s);
uint32_t plic_read_pending (uint32_t int_id);
void plic_set_priority (uint32_t int_id, uint32_t priority);
void plic_clear_pending (uint32_t int_id);
int global_external_lines_default(int idx);
void interrupt_global_enable (void);
void interrupt_global_disable (void);
void interrupt_software_enable (void);
void interrupt_software_disable (void);
void interrupt_timer_enable (void);
void interrupt_timer_disable (void);
void interrupt_external_enable (void);
void interrupt_external_disable (void);
void interrupt_local_enable (int id);
uint32_t secondary_main(void);
uint32_t main(void);

/* Defines to access CSR registers within C code */
#define read_csr(reg) ({ unsigned long __tmp; \
  asm volatile ("csrr %0, " #reg : "=r"(__tmp)); \
  __tmp; })

#define write_csr(reg, val) ({ \
  asm volatile ("csrw " #reg ", %0" :: "rK"(val)); })

#define write_dword(addr, data)                 ((*(volatile uint64_t *)(addr)) = (uint64_t)data)
#define read_dword(addr)                        (*(volatile uint64_t *)(addr))
#define write_word(addr, data)                  ((*(volatile uint32_t *)(addr)) = data)
#define read_word(addr)                         (*(volatile uint32_t *)(addr))
#define write_byte(addr, data)                  ((*(volatile uint8_t *)(addr)) = data)
#define read_byte(addr)                         (*(volatile uint8_t *)(addr))

/* Globals */
void __attribute__((weak, interrupt)) __mtvec_clint_vector_table(void);
void __attribute__((weak, interrupt)) software_handler (void);
void __attribute__((weak, interrupt)) timer_handler (void);
void __attribute__((weak, interrupt)) external_handler (void);
void __attribute__((weak, interrupt)) default_vector_handler (void);
void __attribute__((weak)) default_exception_handler(void);

/* use lock to protect blocks of code so only one hart can execute */
METAL_LOCK_DECLARE(my_lock);

/* Workaround for Unleashed BSP - no global interrupts symbols */
#if (METAL_MAX_GLOBAL_EXT_INTERRUPTS == 0)
#undef METAL_MAX_GLOBAL_EXT_INTERRUPTS
#define METAL_MAX_GLOBAL_EXT_INTERRUPTS     127
#define PLIC_INTERRUPT_LIST_WORKAROUND      TRUE
#endif

/* Global array to hold interrupt ID assignments */
uint32_t plic_interrupt_lines[METAL_MAX_GLOBAL_EXT_INTERRUPTS];

uint32_t timer_isr_counter = 0;
volatile uint32_t global_init = 0;
volatile uint32_t global_int_stuck_pending = 0;
volatile uint32_t global_int_cpu_num = 0;

/* Linker generated symbol that lets us know the boot hart */
extern int __metal_boot_hart;

/* Include secondary_main() since this is the entry point for
 * multi-hart designs using the freedom-metal startup code
 */
uint32_t secondary_main() {

    return main();
}

/* Main - Setup PLIC interrupt handling and describe how to trigger interrupt */
uint32_t main() {

    uint32_t i, priority_thresh, mode;
    uintptr_t mtvec_base, my_hartid, boot_hart;

    /* Write mstatus.mie = 0 to disable all machine interrupts for this hart
     * prior to setup */
    interrupt_global_disable();

    boot_hart = (uintptr_t)&__metal_boot_hart;
    my_hartid = read_csr(mhartid);

    /* Setup mtvec to point to our exception handler table using mtvec.base,
     * and assign mtvec.mode = 1 for CLINT vectored mode of operation. The
     * mtvec.mode field is bit[0] for designs with CLINT, or [1:0] using CLIC */
    mode = MTVEC_MODE_CLINT_VECTORED;
    mtvec_base = (uintptr_t)&__mtvec_clint_vector_table;
    write_csr (mtvec, (mtvec_base | mode));

    /* Initialize a lock for everyone to use, for shared resources */
    if (my_hartid == boot_hart) {

        int rc = metal_lock_init(&my_lock);
        if(rc != 0) {
            puts("Failed to initialize my_lock\n");
            exit(0x18);
        }

        /* Ensure that the lock is initialized before others */
        __asm__ ("fence rw,w"); /* Release semantics */
    }

#if PLIC_PRESENT

    /* Get global PLIC interrupt list and initially disable all interrupts */
    for (i = 0; i < METAL_MAX_GLOBAL_EXT_INTERRUPTS; i++) {

        if (my_hartid == boot_hart) {

        /* Global init using PLIC interrupt list.  We apply a workaround here
         * for any BSP that may not have certain symbols defined.  This will not enable
         * a design without PLIC interrupts to work correctly, rather it is a workaround for
         * BSP's that may not have the proper support in design.dts to create the
         * global interrupt list and the required auto-generated functions to support
         * that list.
         */
#ifdef PLIC_INTERRUPT_LIST_WORKAROUND
        plic_interrupt_lines[i] = global_external_lines_default(i);
#else
        plic_interrupt_lines[i] = __metal_driver_sifive_global_external_interrupts0_interrupt_lines(NULL, i);
#endif
        }

        /* First, each hart disables interrupts in its memory map by default */
        plic_enable_disable(plic_interrupt_lines[i], DISABLE, read_csr(mhartid), MACHINE_INTS);
        if (my_hartid != 0) {
            /* Hart0 on standard multi-core configs do not have Supervisor mode */
            plic_enable_disable(plic_interrupt_lines[i], DISABLE, read_csr(mhartid), SUPERVISOR_INTS);
        }
    }

    /* Allow boot hart to continue and setup PLIC global enables and priorities,
     * the rest wait here until that is complete */
    if (my_hartid != boot_hart) {
        while (!global_init);
    }

    /* Setup global PLIC enables and priorities */
    for (i = 0; i < METAL_MAX_GLOBAL_EXT_INTERRUPTS; i++) {

        /* Enable interrupts on boot hart for testing, optionally on other cores */
        if (my_hartid == boot_hart) {

            /* Attempt to clear all PLIC pending interrupts before we begin */
            plic_clear_pending (plic_interrupt_lines[i]);

            /* Set Priority - valid values are 1 - 7.  A value of 0 means disabled */
            plic_set_priority (plic_interrupt_lines[i], 0x2);

            /* Write enables for each machine interrupt for boot hart */
            plic_enable_disable(plic_interrupt_lines[i], ENABLE, read_csr(mhartid), MACHINE_INTS);
            if (my_hartid != 0) {
                /* Hart0 on standard multi-core configs do not have Supervisor mode */
                plic_enable_disable(plic_interrupt_lines[i], ENABLE, read_csr(mhartid), SUPERVISOR_INTS);
            }
        }
        else {
#if ENABLE_PLIC_ALL_HARTS
            /* Enable on this hart if we choose to, or add functionality to
             * do this selectively based on the hart ID and the application
             * requirements.
             */
            plic_enable_disable(plic_interrupt_lines[i], ENABLE, read_csr(mhartid), MACHINE_INTS);
            plic_enable_disable(plic_interrupt_lines[i], ENABLE, read_csr(mhartid), SUPERVISOR_INTS);
#endif
        }
    }

    /* The global init is complete by the boot hart, flag the others to resume */
    global_init = 1;
    __asm__("fence");

    /* Set global threshold register for each hart to 0x1 to allow all
     * interrupt of 0x2 or higher to trigger.  Read it back to verify
     * we have the proper offset per hartid.  This code should run on
     * each hart since each hart has its own threshold register.
     */
    priority_thresh = 0x1;
    write_word(PLIC_THRESHOLD_ADDR(read_csr(mhartid)), priority_thresh);
    i = read_word(PLIC_THRESHOLD_ADDR(read_csr(mhartid)));
    if (i != priority_thresh) {
        printf ("Priority Threshold Value Not Written Correctly for CPU %d!\n", read_csr(mhartid));
        printf ("Read: 0x%8x, Expected: 0x%8x\n", i, priority_thresh);
    }

#else
#error "This design does not have a PLIC...Exiting."
    exit(0x77);
#endif  /* #if PLIC_PRESENT */

    /* Enable External interrupts in mie CSR, which come from the PLIC.
     * Software, timer, and local interrupts 16->XLEN also live here */
    interrupt_external_enable();

    /* Global enable per hart in mstatus.mie */
    if (my_hartid == boot_hart) {
       interrupt_global_enable();  /* enable boot hart for this example */
    }
    else {
#if ENABLE_PLIC_ALL_HARTS
        interrupt_global_enable();  /* enable interrupt globally on this hart */
#else
        interrupt_global_disable();  /* disabled globally on this hart */
#endif
    }

    /* print message from each hart */
    metal_lock_take(&my_lock);
    printf ("Hi! This is CPU %d\n", read_csr(mhartid));
    fflush(stdout);
    if (global_int_stuck_pending) {
        printf ("CPU %d still has interrupt %d pending!\n", global_int_cpu_num, global_int_stuck_pending);
        fflush(stdout);
    }
    metal_lock_give(&my_lock);

    /*
     * At this point, it's up to the user to trigger a global PLIC interrupt.
     * On the Arty FPGA board, this can be accomplished by using the switches
     * on standard core designs such as S76, U54, and others.
     *
     * Adding a while(1); loop here while asserting a global interrupt will
     * cause the hart to hit the external_handler() interrupt function.
     *
     * Otherwise we exit with a pass value of 0x0.
     */

    return 0;
}

/* Enable or disable a PLIC interrupt on a given hart.
 * One enable bit per interrupt, 32 enable bits per register.
 * Each hart (CPU) has its own enable register block, and this
 * function supports the Machine mode interrupt enable region.
 */
void plic_enable_disable (uint32_t int_id, uint32_t en_dis, uint32_t hartid, uint32_t m_or_s) {

    uint32_t reg = int_id / 32;      /* get index */
    uint32_t bitshift = int_id % 32; /* remainder is bit position */
    uint32_t enable_reg;
    uintptr_t plic_enable_addr;

    /* calculate address based on input parameters, hart0 on SiFive standard cores designs
     * typically don't have S-mode, so their base address is calculated independently
     */
    if ((hartid == 0) && (m_or_s == MACHINE_INTS)) {
        plic_enable_addr = ((PLIC_ENABLE_BASE_ADDR + PLIC_HART0_ENABLE_BASE_ADDR) + (PLIC_REGWIDTH * reg));
    }
    else if  (m_or_s == MACHINE_INTS) {
        plic_enable_addr = PLIC_ENABLE_BASE_ADDR + PLIC_HART1_ENABLE_BASE_ADDR;
        plic_enable_addr += ((hartid - 1) * PLIC_HARTx_OFFSET);
        plic_enable_addr += (PLIC_REGWIDTH * reg);
    }
    else if (m_or_s == SUPERVISOR_INTS) {
        plic_enable_addr = PLIC_ENABLE_SUPERVISOR_BASE_ADDR;
        plic_enable_addr += ((hartid - 1) * PLIC_HARTx_OFFSET);
        plic_enable_addr += (PLIC_REGWIDTH * reg);
    }
    else {
        return;  // not valid, do nothing
    }

    /* get current register value */
    enable_reg = read_word (plic_enable_addr);
    enable_reg = (en_dis == ENABLE) ? (enable_reg | (1 << bitshift)) : enable_reg & ~(1 << bitshift);

    /* Write it back */
    write_word (plic_enable_addr, enable_reg);
}

/* Read PLIC pending bit for a certain interrupt
 * return 0x1 if pending
 * return 0x0 if not pending
 *
 * NOTE: The pending registers are based on interrupt ID, which is the
 * same number for all harts (CPUs) in the system.
 * So, there is no need to check mhartid in the pending register memory map.
 */
uint32_t plic_read_pending (uint32_t int_id) {

    uint32_t reg = int_id / 32;      /* get index */
    uint32_t bitshift = int_id % 32; /* remainder is bit position */
    uint32_t plic_pending_addr = (PLIC_PENDING_BASE_ADDR + (PLIC_REGWIDTH * reg));
    uint32_t pending_reg = read_word (plic_pending_addr);

    /* return single bit for pending status */
    pending_reg >>= bitshift;
    return (pending_reg & 0x1);
}

/* Write PLIC pending bit to clear pending status
 */
void plic_clear_pending (uint32_t int_id) {

    uint32_t reg = int_id / 32;      /* get index */
    uint32_t bitshift = int_id % 32; /* remainder is bit position */
    uint32_t plic_pending_addr = (PLIC_PENDING_BASE_ADDR + (PLIC_REGWIDTH * reg));
    uint32_t pending_bit = (1 << bitshift);

    /* write pending bit to clear if it's set */
    if (read_word(plic_pending_addr) & (pending_bit)) {
        write_word (plic_pending_addr, pending_bit);
    }
}

int global_external_lines_default(int idx)
{
    /* return a linear list so that we can enable all lines by default,
     * since this is what U74-MC and U54-MC currently do.
     */
    return (idx + 1);
}

/* Set priority of a given PLIC interrupt.
 * Priority is a 3-bit field within a 32-register.
 *
 * NOTE: The priority registers relate to each individual interrupt iD,
 * so there is no need for mhartid checks within this memory map.
 */
void plic_set_priority (uint32_t int_id, uint32_t priority) {

    uint32_t priority_reg_addr = PLIC_PRIORITY_ADDR(int_id);
    write_word(priority_reg_addr, priority);
}


/* External Interrupt ID #11 - handles all global interrupts from PLIC.
 * If multiple pending interrupts are queued up for this hart, then we
 * are able to service them without the additional overhead of exiting
 * the handler and re-entering, so we use a for(;;) loop to accomplish this.
 */
void __attribute__((weak, interrupt)) external_handler (void) {

    uintptr_t hartid = read_csr(mhartid);
    uint32_t max_pending_timeout = 0x400, still_pending = TRUE;
    uint32_t claim_complete_id;

    while ((still_pending == TRUE) && (max_pending_timeout != 0)) {

        /* read PLIC claim register */
        claim_complete_id = read_word(PLIC_CLAIM_COMPLETE_ADDR(hartid));

        if (claim_complete_id != 0) {
            /* Call interrupt specific software function (Or call s/w table function here) */
            plic_sw_handler(claim_complete_id);
        }

        /* read pending register */
        uint32_t plic_int_pend_bit = plic_read_pending (claim_complete_id);

        /* If we have a valid claim ID then ensure pending has gone low */
        if ((plic_int_pend_bit != 0) && (claim_complete_id != 0)) {
            still_pending = TRUE;   /* keep true, another interrupt is pending */
            max_pending_timeout--;  /* decrement timeout to allow an exit at some point */

            /* Is there custom IP connected that has a pending flag that needs to be cleared? */
        }
        else {
            still_pending = FALSE;
            global_int_stuck_pending = FALSE;
        }

        if (claim_complete_id != 0) {
            /* write it back to complete interrupt */
            write_word(PLIC_CLAIM_COMPLETE_ADDR(hartid), claim_complete_id);
        }
    } /* while ((still_pending == TRUE) && (max_pending_timeout != 0)) */

    if (still_pending == TRUE) {
        /* we timed out, capture interrupt causing trouble for tracking */
        global_int_stuck_pending = claim_complete_id;
    }

    global_int_cpu_num = hartid;  /* last CPU to hit this handler, for tracking */
}

/* Global software support for different interrupts */
void plic_sw_handler(uint32_t plic_id) {

    if (plic_id == plic_interrupt_lines[0]) {
        /* Add customization as needed depending on global interrupt source */
    }
    //else if...
}

void __attribute__((weak, interrupt)) software_handler (void) {
    /* Add functionality if desired */
}

void __attribute__((weak, interrupt)) timer_handler (void) {
    uintptr_t mtime = read_csr(time);

    printf ("Timer Handler! Count: %d\n", timer_isr_counter++);
    mtime += 100*RTC_FREQ;
    write_dword(MTIMECMP_BASE_ADDR, mtime);    /* next timer interrupt is sometime in the future */
}

void __attribute__((weak, interrupt)) default_vector_handler (void) {
    /* Add functionality if desired */
    while (1);
}

void __attribute__((weak)) default_exception_handler(void) {

    /* Read mcause to understand the exception type */
    uintptr_t mcause = read_csr(mcause);
    uintptr_t mepc = read_csr(mepc);
    uintptr_t mtval = read_csr(mtval);
    uintptr_t code = MCAUSE_CODE(mcause);

    printf ("Exception Hit! mcause: 0x%08x, mepc: 0x%08x, mtval: 0x%08x\n", mcause, mepc, mtval);
    printf ("Mcause Exception Code: 0x%08x\n", code);
    printf("Now Exiting...\n");

    /* Exit here using non-zero return code */
    exit (0xEE);
}

void interrupt_global_enable (void) {
    uintptr_t m;
    __asm__ volatile ("csrrs %0, mstatus, %1" : "=r"(m) : "r"(METAL_MIE_INTERRUPT));
}

void interrupt_global_disable (void) {
    uintptr_t m;
    __asm__ volatile ("csrrc %0, mstatus, %1" : "=r"(m) : "r"(METAL_MIE_INTERRUPT));
}

void interrupt_software_enable (void) {
    uintptr_t m;
    __asm__ volatile ("csrrs %0, mie, %1" : "=r"(m) : "r"(METAL_LOCAL_INTERRUPT_SW));
}

void interrupt_software_disable (void) {
    uintptr_t m;
    __asm__ volatile ("csrrc %0, mie, %1" : "=r"(m) : "r"(METAL_LOCAL_INTERRUPT_SW));
}

void interrupt_timer_enable (void) {
    uintptr_t m;
    __asm__ volatile ("csrrs %0, mie, %1" : "=r"(m) : "r"(METAL_LOCAL_INTERRUPT_TMR));
}

void interrupt_timer_disable (void) {
    uintptr_t m;
    __asm__ volatile ("csrrc %0, mie, %1" : "=r"(m) : "r"(METAL_LOCAL_INTERRUPT_TMR));
}

void interrupt_external_enable (void) {
    uintptr_t m;
    __asm__ volatile ("csrrs %0, mie, %1" : "=r"(m) : "r"(METAL_LOCAL_INTERRUPT_EXT));
}

void interrupt_external_disable (void) {
    unsigned long m;
    __asm__ volatile ("csrrc %0, mie, %1" : "=r"(m) : "r"(METAL_LOCAL_INTERRUPT_EXT));
}

void interrupt_local_enable (int id) {
    uintptr_t b = 1 << id;
    uintptr_t m;
    __asm__ volatile ("csrrs %0, mie, %1" : "=r"(m) : "r"(b));
}
