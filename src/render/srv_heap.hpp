#pragma once
//
// Violet - a tiny SRV descriptor allocator
//
// ---------------------------------------------------------------------------
// What a descriptor actually is
// ---------------------------------------------------------------------------
//
// In D3D12 the GPU never sees a pointer to a texture. It sees a *descriptor*: a
// small, fixed-size struct the driver understands, which describes "here is a
// texture, this format, this many mips". Descriptors live in a descriptor
// *heap* - a flat array of them - and shaders index into that array.
//
// Crucially, D3D12 does not manage that array for you. Unlike D3D11, where you
// just handed the API a texture pointer, here you own the memory and you decide
// which slot each texture goes in. That is the whole reason this file exists.
//
// ImGui needs slots for its font atlas and for any texture you draw with
// ImGui::Image. As of 1.92 the backend allocates and frees them dynamically
// (fonts can now be rebuilt at runtime), so it asks us for two callbacks -
// "give me a slot" and "here, have it back". This is the smallest correct
// implementation of that: a fixed array plus a free list of unused indices.
//
#include <d3d12.h>

#include <cassert>
#include <vector>

namespace violet::render
{
    class SrvHeapAllocator
    {
    public:
        void create(ID3D12Device* device, ID3D12DescriptorHeap* heap, int capacity)
        {
            assert(m_heap == nullptr && "already created");

            m_heap      = heap;
            m_cpu_start = heap->GetCPUDescriptorHandleForHeapStart();
            m_gpu_start = heap->GetGPUDescriptorHandleForHeapStart();

            // Descriptor size is vendor-specific - an NVIDIA SRV descriptor is
            // not necessarily the same number of bytes as an AMD one. You must
            // always ask the device rather than assuming, which is why heap
            // indexing is index * increment and never index * sizeof(anything).
            m_increment = device->GetDescriptorHandleIncrementSize(
                D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV);

            // Hand out low indices first, purely so the layout is easy to read
            // in a graphics debugger.
            m_free.reserve(static_cast<std::size_t>(capacity));
            for (int i = capacity - 1; i >= 0; --i)
                m_free.push_back(i);
        }

        void destroy()
        {
            m_heap = nullptr;
            m_free.clear();
        }

        void alloc(D3D12_CPU_DESCRIPTOR_HANDLE* out_cpu, D3D12_GPU_DESCRIPTOR_HANDLE* out_gpu)
        {
            assert(!m_free.empty() && "SRV heap exhausted - raise the capacity");

            const int index = m_free.back();
            m_free.pop_back();

            out_cpu->ptr = m_cpu_start.ptr + static_cast<SIZE_T>(index) * m_increment;
            out_gpu->ptr = m_gpu_start.ptr + static_cast<UINT64>(index) * m_increment;
        }

        void free(D3D12_CPU_DESCRIPTOR_HANDLE cpu, D3D12_GPU_DESCRIPTOR_HANDLE gpu)
        {
            const auto cpu_index = static_cast<int>((cpu.ptr - m_cpu_start.ptr) / m_increment);
            const auto gpu_index = static_cast<int>((gpu.ptr - m_gpu_start.ptr) / m_increment);

            assert(cpu_index == gpu_index && "handles came from different heaps");
            (void)gpu_index;   // read only by the assert, which vanishes in release builds

            m_free.push_back(cpu_index);
        }

    private:
        ID3D12DescriptorHeap*       m_heap      = nullptr;
        D3D12_CPU_DESCRIPTOR_HANDLE m_cpu_start{};
        D3D12_GPU_DESCRIPTOR_HANDLE m_gpu_start{};
        UINT                        m_increment = 0;
        std::vector<int>            m_free;
    };
}
