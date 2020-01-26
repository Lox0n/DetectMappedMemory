#include <windows.h>
#include <cstdio>

void Scan()
{
	MEMORY_BASIC_INFORMATION mbi{ };

	for (
		ULONG_PTR cursor = NULL;
		VirtualQuery(PVOID(cursor), &mbi, sizeof mbi) >= 0;
		cursor = ULONG_PTR(mbi.BaseAddress) + mbi.RegionSize
		)
	{
		const auto IsExecutableMemory = (mbi.State & MEM_COMMIT) && ((mbi.Protect & PAGE_EXECUTE_READWRITE) || (mbi.Protect & PAGE_EXECUTE_READ)) && !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD) && !(mbi.State & MEM_RELEASE);

		if (!IsExecutableMemory)
			continue;

		const auto IsNativeMemory =
			(mbi.Type != MEM_PRIVATE || mbi.Type != MEM_MAPPED) &&
			((ULONG_PTR(mbi.BaseAddress) & 0xFF0000000000) != 0x7F0000000000 &&
			(ULONG_PTR(mbi.BaseAddress) & 0xFFF000000000) != 0x7F000000000 &&
			(ULONG_PTR(mbi.BaseAddress) & 0xFFFFF0000000) != 0x70000000);

		if (!IsNativeMemory)
			continue;

		PVOID Base = nullptr;
		if (RtlPcToFileHeader(PVOID(cursor), &Base))
			continue;

		printf("Mapped Image: %p\n", cursor);
		break;
	}
}

int main()
{
	Scan();

	return 0;
}