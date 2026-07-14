#include "hk.h"

//
// jmp QWORD PTR [rip+0x0]
//
static const UCHAR HkpDetour[] = {
	0xff, 0x25, 0x00, 0x00, 0x00, 0x00
};

#define FULL_DETOUR_SIZE			(sizeof(HkpDetour) + sizeof(PVOID))
#define INTERLOCKED_EXCHANGE_SIZE	(16ul)
#define HK_POOL_TAG					('  kh')

_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS HkpReplaceCode16Bytes(
	_In_ PVOID	Address,
	_In_ PUCHAR	Replacement
)
{
	//
	// Verifica o alinhamento adequado. cmpxchg16b funciona apenas com endereços alinhados a 16 bytes.
	//
	if ((ULONG64)Address != ((ULONG64)Address & ~0xf))
	{
		return STATUS_DATATYPE_MISALIGNMENT;
	}

	//
	// Cria uma lista de descritores de memória para mapear a memória somente leitura (ou RX) como leitura/escrita.
	//
	PMDL Mdl = IoAllocateMdl(Address, INTERLOCKED_EXCHANGE_SIZE, FALSE, FALSE, NULL);
	if (Mdl == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//
	// Torna as páginas de memória residentes na RAM e garante que elas não serão paginadas (paged out).
	//
	__try
	{
		MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(Mdl);

		return STATUS_INVALID_ADDRESS;
	}

	//
	// Cria um novo mapeamento para a memória somente leitura.
	//
	PLONG64 RwMapping = MmMapLockedPagesSpecifyCache(
		Mdl,
		KernelMode,
		MmNonCached,
		NULL,
		FALSE,
		NormalPagePriority
	);

	if (RwMapping == NULL)
	{
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);

		return STATUS_INTERNAL_ERROR;
	}

	//
	// Define a proteção da página do novo mapeamento para leitura/escrita a fim de modificá-la.
	//
	NTSTATUS Status = MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		MmUnmapLockedPages(RwMapping, Mdl);
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);

		return Status;
	}

	LONG64 PreviousContent[2];
	PreviousContent[0] = RwMapping[0];
	PreviousContent[1] = RwMapping[1];

	//
	// Substitui 16 bytes de código usando o mapeamento leitura/escrita criado.
	// O Interlocked compare and exchange (cmpxchg16b) é usado para evitar problemas de concorrência.
	//
	InterlockedCompareExchange128(
		RwMapping,
		((PLONG64)Replacement)[1],
		((PLONG64)Replacement)[0],
		PreviousContent
	);

	//
	// Desbloqueia e desfaz o mapeamento das páginas, libera a MDL.
	//
	MmUnmapLockedPages(RwMapping, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);

	return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
static VOID HkpPlaceDetour(
	_In_ PVOID Address,
	_In_ PVOID Destination
)
{
	//
	// Salva a instrução de pulo (jump) e o destino do desvio (detour).
	// Isso criará o código como mostrado abaixo:
	// +0	jmp QWORD PTR [rip+0x0]
	// +6	0x................
	//
	RtlCopyMemory((PUCHAR)Address, HkpDetour, sizeof(HkpDetour));
	RtlCopyMemory((PUCHAR)Address + sizeof(HkpDetour), &Destination, sizeof(PVOID));
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkRestoreFunction(
	_In_ PVOID	 HookedFunction,
	_In_ PVOID	 OriginalTrampoline
)
{
	PUCHAR OriginalBytes = (PUCHAR)OriginalTrampoline - INTERLOCKED_EXCHANGE_SIZE;

	//
	// Se isso falhar, provavelmente teremos um bugcheck de qualquer maneira...
	//
	NTSTATUS Status = HkpReplaceCode16Bytes(HookedFunction, OriginalBytes);

	//
	// Aguarda 10 ms para garantir que nenhum código pule para o trampolim após a liberação.
	//
	LARGE_INTEGER DelayInterval;
	DelayInterval.QuadPart = -100000;
	KeDelayExecutionThread(KernelMode, FALSE, &DelayInterval);

	//
	// Libera os recursos.
	//
	ExFreePoolWithTag(OriginalBytes, HK_POOL_TAG);

	return Status;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkDetourFunction(
	_In_ PVOID	 TargetFunction,
	_In_ PVOID	 Hook,
	_In_ SIZE_T  CodeLength,
	_Out_ PVOID* OriginalTrampoline
)
{
	//
	// Verifica se o CodeLength é grande o suficiente para armazenar o desvio.
	//
	if (CodeLength < FULL_DETOUR_SIZE)
	{
		return STATUS_INVALID_PARAMETER_3;
	}

	//
	// NonPagedPool é usado para ser compatível com funções que rodam em IRQL alto (>= DISPATCH_LEVEL).
	//
	PUCHAR Trampoline = ExAllocatePoolWithTag(
		NonPagedPool,
		INTERLOCKED_EXCHANGE_SIZE + FULL_DETOUR_SIZE + CodeLength,
		HK_POOL_TAG
	);
	if (Trampoline == NULL)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//
	// Salva 16 bytes originais para restaurar a função depois (necessário para o HkRestoreFunction).
	//
	RtlCopyMemory(Trampoline, TargetFunction, INTERLOCKED_EXCHANGE_SIZE);

	//
	// Cria o trampolim para a função original contendo os bytes originais e um pulo para a função + CodeLength.
	//
	RtlCopyMemory(Trampoline + INTERLOCKED_EXCHANGE_SIZE, TargetFunction, CodeLength);
	HkpPlaceDetour(Trampoline + INTERLOCKED_EXCHANGE_SIZE + CodeLength, (PVOID)((ULONG_PTR)TargetFunction + CodeLength));

	//
	// Gera os bytes do desvio.
	//
	UCHAR DetourBytes[INTERLOCKED_EXCHANGE_SIZE];

	HkpPlaceDetour(DetourBytes, Hook);
	RtlCopyMemory(
		(PUCHAR)DetourBytes + FULL_DETOUR_SIZE,
		(PUCHAR)TargetFunction + FULL_DETOUR_SIZE,
		INTERLOCKED_EXCHANGE_SIZE - FULL_DETOUR_SIZE
	);

	//
	// Aplica o desvio na função alvo.
	//
	NTSTATUS Status = HkpReplaceCode16Bytes(TargetFunction, DetourBytes);
	if (!NT_SUCCESS(Status))
	{
		ExFreePoolWithTag(Trampoline, HK_POOL_TAG);
	}
	else
	{
		*OriginalTrampoline = Trampoline + INTERLOCKED_EXCHANGE_SIZE;
	}

	return Status;
}
