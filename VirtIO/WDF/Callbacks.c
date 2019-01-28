/*
 * Implementation of virtio_system_ops VirtioLib callbacks
 *
 * Copyright (c) 2016-2017 Red Hat, Inc.
 *
 * Author(s):
 *  Ladi Prosek <lprosek@redhat.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met :
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and / or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of their contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "osdep.h"
#include "virtio_pci.h"
#include "VirtIOWdf.h"
#include "private.h"

static BOOLEAN mem_realloc_buffer(VirtIODevice *device)
{
    struct dma_item *prev = device->dma_map;
    device->dma_map = ExAllocatePoolWithTag(
        NonPagedPool,
        (device->dma_items_max_count + DMA_BUFFER_QUANT_SIZE) * sizeof(struct dma_item),
        VIRTIO_DMA_MEMORY_TAG);

    if (device->dma_map != NULL)
    {
        RtlZeroMemory(device->dma_map, (device->dma_items_max_count + DMA_BUFFER_QUANT_SIZE) * sizeof(struct dma_item));
        if (prev != NULL)
        {
            RtlCopyMemory(device->dma_map, prev, device->dma_items_max_count * sizeof(struct dma_item));
            ExFreePoolWithTag(prev, VIRTIO_DMA_MEMORY_TAG);
        }
        else
        {
            device->dma_map[0].prev = -1;
            device->dma_map[0].next = 0;
        }

        device->dma_items_max_count = device->dma_items_max_count + DMA_BUFFER_QUANT_SIZE;
        return TRUE;
        }
    else
    {
        device->dma_map = prev;
        return FALSE;
    }
    }

static LONGLONG dma_mem_find_next_item(VirtIODevice *device, void* virt)
{
    if (device->dma_first_index == device->dma_last_index)
        return 0;

    LONGLONG i = device->dma_first_index;
    while (i >= 0) //device->dma_map[i].next && i < device->dma_item_index && 
    {
        if (device->dma_map[i].dma_virtual_address > virt)
        {
            return i;
        }

        i = device->dma_map[i].next;
    }

    return -1;
}

static LONGLONG dma_mem_get_prev_item(VirtIODevice *device, LONGLONG next)
{
    if (next >= 0)
        return device->dma_map[next].prev;
    else
        return -1;

}

static LONGLONG get_dma_map_get_item_index(VirtIODevice *device, void *virt)
{
    LONGLONG i = device->dma_first_index;
    while (i >= 0) //i < device->dma_last_index && 
    {
        if (virt >= device->dma_map[i].dma_virtual_address && (u8*)virt < ((u8*)device->dma_map[i].dma_virtual_address + device->dma_map[i].size))
        {
            return i;
        }
        else
            i = device->dma_map[i].next;
    }

    return -1;
}

static WDFCOMMONBUFFER get_common_buffer(VirtIODevice *device, void *virt, BOOLEAN clear)
{
    if (device == NULL || virt == NULL)
        return NULL;

    WDFCOMMONBUFFER buffer = NULL;

    LONGLONG i = get_dma_map_get_item_index(device, virt);
    if (i >= 0)
    {
        buffer = device->dma_map[i].dma_common_buffer;
        if (clear)
        {
            RtlZeroMemory(&device->dma_map[i], sizeof(struct dma_item));
            device->dma_map[i].prev = -1;
            device->dma_map[i].next = device->dma_item_index;
            device->dma_item_index = i;
        }
    }

    return buffer;
}

static void *mem_alloc_contiguous_pages(void *context, size_t size)
{
    void *ret = NULL;
    NTSTATUS status;
    WDFDMAENABLER dmaEnabler = NULL;
    WDFCOMMONBUFFER buffer = NULL;
    VirtIODevice *device = (VirtIODevice*)context;

    if (device != NULL)
    {
        dmaEnabler = device->dmaEnabler;
        if (dmaEnabler != NULL)
        {
            if (device->dma_item_index >= device->dma_items_max_count)
            {
                mem_realloc_buffer(device);
            }

            status = WdfCommonBufferCreate(dmaEnabler, size, WDF_NO_OBJECT_ATTRIBUTES, &buffer);
            if (device->dma_item_index < device->dma_items_max_count)
            {
                if (status == STATUS_SUCCESS)
                {
                    LONGLONG cur = device->dma_item_index;
                    LONGLONG next_free = -1;
                    if (device->dma_map[cur].prev == -1)
                        device->dma_item_index = device->dma_map[cur].next;
                    else
                        device->dma_item_index++;

                    ret = WdfCommonBufferGetAlignedVirtualAddress(buffer);
                    device->dma_map[cur].dma_common_buffer = buffer;
                    device->dma_map[cur].dma_virtual_address = ret;
                    device->dma_map[cur].dma_physical_address = WdfCommonBufferGetAlignedLogicalAddress(buffer);
                    device->dma_map[cur].size = size;

                    //sort
                    LONGLONG next = dma_mem_find_next_item(device, ret);
                    LONGLONG prev = dma_mem_get_prev_item(device, next);

                    device->dma_map[cur].next = next;
                    device->dma_map[cur].prev = prev;

                    if (next >= 0)
                    {
                        device->dma_map[next].prev = cur;
                    }
                    else //this is last item in sorted array
                    {
                        device->dma_last_index = cur;
                    }

                    if (prev >= 0)
                    {
                        device->dma_map[prev].next = cur;
                    }
                    else //this is first item in sorted array
                    {
                        device->dma_first_index = cur;
                    }
                }
            }
        }
    }

    if (ret != NULL)
    {
        RtlZeroMemory(ret, size);
    }

    return ret;
}

static void mem_free_contiguous_pages(void *context, void *virt)
{
    if (context != NULL)
    {
        WDFCOMMONBUFFER buffer = get_common_buffer((VirtIODevice *)context, virt, TRUE);
        if (buffer != NULL)
        {
            WdfObjectDelete(buffer);
        }
    }
}

static ULONGLONG mem_get_physical_address(void *context, void *virt)
{
    VirtIODevice *device = (VirtIODevice*)context;

    LONGLONG i = get_dma_map_get_item_index(device, virt);
    if (i >= 0)
    {
        LONGLONG delta = (u8*)virt - (u8*)device->dma_map[i].dma_virtual_address;
        return device->dma_map[i].dma_physical_address.QuadPart + delta;
    }

    return 0;
}

static void *mem_alloc_nonpaged_block(void *context, size_t size)
{
    PVIRTIO_WDF_DRIVER pWdfDriver = (PVIRTIO_WDF_DRIVER)context;

    PVOID addr = ExAllocatePoolWithTag(
        NonPagedPool,
        size,
        pWdfDriver->MemoryTag);
    if (addr) {
        RtlZeroMemory(addr, size);
    }
    return addr;
}

static void mem_free_nonpaged_block(void *context, void *addr)
{
    PVIRTIO_WDF_DRIVER pWdfDriver = (PVIRTIO_WDF_DRIVER)context;

    ExFreePoolWithTag(
        addr,
        pWdfDriver->MemoryTag);
}

static int pci_read_config_byte(void *context, int where, u8 *bVal)
{
    return PCIReadConfig((PVIRTIO_WDF_DRIVER)context, where, bVal, sizeof(*bVal));
}

static int pci_read_config_word(void *context, int where, u16 *wVal)
{
    return PCIReadConfig((PVIRTIO_WDF_DRIVER)context, where, wVal, sizeof(*wVal));
}

static int pci_read_config_dword(void *context, int where, u32 *dwVal)
{
    return PCIReadConfig((PVIRTIO_WDF_DRIVER)context, where, dwVal, sizeof(*dwVal));
}

static PVIRTIO_WDF_BAR find_bar(void *context, int bar)
{
    PVIRTIO_WDF_DRIVER pWdfDriver = (PVIRTIO_WDF_DRIVER)context;
    PSINGLE_LIST_ENTRY iter = &pWdfDriver->PCIBars;
    
    while (iter->Next != NULL) {
        PVIRTIO_WDF_BAR pBar = CONTAINING_RECORD(iter->Next, VIRTIO_WDF_BAR, ListEntry);
        if (pBar->iBar == bar) {
            return pBar;
        }
        iter = iter->Next;
    }
    return NULL;
}

static size_t pci_get_resource_len(void *context, int bar)
{
    PVIRTIO_WDF_BAR pBar = find_bar(context, bar);
    return (pBar ? pBar->uLength : 0);
}

static void *pci_map_address_range(void *context, int bar, size_t offset, size_t maxlen)
{
    PVIRTIO_WDF_BAR pBar = find_bar(context, bar);
    if (pBar) {
        if (pBar->pBase == NULL) {
            ASSERT(!pBar->bPortSpace);
#if defined(NTDDI_WINTHRESHOLD) && (NTDDI_VERSION >= NTDDI_WINTHRESHOLD)
            pBar->pBase = MmMapIoSpaceEx(
                pBar->BasePA,
                pBar->uLength,
                PAGE_READWRITE | PAGE_NOCACHE);
#else
            pBar->pBase = MmMapIoSpace(pBar->BasePA, pBar->uLength, MmNonCached);
#endif
        }
        if (pBar->pBase != NULL && offset < pBar->uLength) {
            return (char *)pBar->pBase + offset;
        }
    }
    return NULL;
}

static u16 vdev_get_msix_vector(void *context, int queue)
{
    PVIRTIO_WDF_DRIVER pWdfDriver = (PVIRTIO_WDF_DRIVER)context;
    u16 vector = VIRTIO_MSI_NO_VECTOR;

    if (queue >= 0) {
        /* queue interrupt */
        if (pWdfDriver->pQueueParams != NULL) {
            vector = PCIGetMSIInterruptVector(pWdfDriver->pQueueParams[queue].Interrupt);
        }
    }
    else {
        /* on-device-config-change interrupt */
        vector = PCIGetMSIInterruptVector(pWdfDriver->ConfigInterrupt);
    }

    return vector;
}

static void vdev_sleep(void *context, unsigned int msecs)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UNREFERENCED_PARAMETER(context);

    if (KeGetCurrentIrql() <= APC_LEVEL) {
        LARGE_INTEGER delay;
        delay.QuadPart = Int32x32To64(msecs, -10000);
        status = KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }

    if (!NT_SUCCESS(status)) {
        /* fall back to busy wait if we're not allowed to sleep */
        KeStallExecutionProcessor(1000 * msecs);
    }
}

extern u32 ReadVirtIODeviceRegister(ULONG_PTR ulRegister);
extern void WriteVirtIODeviceRegister(ULONG_PTR ulRegister, u32 ulValue);
extern u8 ReadVirtIODeviceByte(ULONG_PTR ulRegister);
extern void WriteVirtIODeviceByte(ULONG_PTR ulRegister, u8 bValue);
extern u16 ReadVirtIODeviceWord(ULONG_PTR ulRegister);
extern void WriteVirtIODeviceWord(ULONG_PTR ulRegister, u16 bValue);

VirtIOSystemOps VirtIOWdfSystemOps = {
    .vdev_read_byte = ReadVirtIODeviceByte,
    .vdev_read_word = ReadVirtIODeviceWord,
    .vdev_read_dword = ReadVirtIODeviceRegister,
    .vdev_write_byte = WriteVirtIODeviceByte,
    .vdev_write_word = WriteVirtIODeviceWord,
    .vdev_write_dword = WriteVirtIODeviceRegister,
    .mem_alloc_contiguous_pages = mem_alloc_contiguous_pages,
    .mem_free_contiguous_pages = mem_free_contiguous_pages,
    .mem_get_physical_address = mem_get_physical_address,
    .mem_alloc_nonpaged_block = mem_alloc_nonpaged_block,
    .mem_free_nonpaged_block = mem_free_nonpaged_block,
    .pci_read_config_byte = pci_read_config_byte,
    .pci_read_config_word = pci_read_config_word,
    .pci_read_config_dword = pci_read_config_dword,
    .pci_get_resource_len = pci_get_resource_len,
    .pci_map_address_range = pci_map_address_range,
    .vdev_get_msix_vector = vdev_get_msix_vector,
    .vdev_sleep = vdev_sleep,
};
