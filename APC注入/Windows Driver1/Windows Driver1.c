#include "x.h"

ULONG NameOffset;													//EPROCESS�����ֵ�ƫ��ֵ
KEINITIALIZEAPC KeInitializeApc;									//������ʼ��APC�ĺ���
KEINSERTQUEUEAPC KeInsertQueueApc;									//������APC���뵽��Ӧ�̵߳ĺ���

ULONG_PTR JudgeAlertable(ULONG_PTR ThreadAddress)
{
	UCHAR *FuncMemory;
	ULONG_PTR RetValue;
	FuncMemory = sfExAllocatePool(sizeof(AlertableCode));
	if (FuncMemory == NULL)
	{
		KdPrint(("�����ڴ�ʧ�ܣ�\n"));
		return 0;
	}
	RtlCopyMemory(FuncMemory, AlertableCode, sizeof(AlertableCode));
	RetValue = ((JUDGEALERTABLE)(FuncMemory))(ThreadAddress);
	sfExFreePool(FuncMemory);
	return RetValue;
}

ULONG_PTR JudgeQueueable(ULONG_PTR ThreadAddress)
{
	UCHAR *FuncMemory;
	ULONG_PTR RetValue;
	FuncMemory = sfExAllocatePool(sizeof(QueueableCode));
	if (FuncMemory == NULL)
	{
		KdPrint(("�����ڴ�ʧ�ܣ�\n"));
		return 0;
	}
	RtlCopyMemory(FuncMemory, QueueableCode, sizeof(QueueableCode));
	RetValue = ((JUDGEQUEUEABLE)(FuncMemory))(ThreadAddress);
	sfExFreePool(FuncMemory);
	return RetValue;
}

VOID KernelRoutine(__in KAPC *Apc,									//�������ͷ�һ��APC������ΪĿ����ע��DLL����Ҫȥʹ��USER_MODE APC
	__deref_inout_opt PKNORMAL_ROUTINE *NormalRoutine,				//�������ʵ���Ͼ��ǳ�ʼ��APC��ʱ�����NormalRoutine�����Բ��У�������KernelRoutinue�����NormalRoutinue��仰��
	__deref_inout_opt PVOID *NormalContext,			
	__deref_inout_opt PVOID *SystemArgument1,
	__deref_inout_opt PVOID *SystemArgument2
	)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);
	sfExFreePool(Apc);
}

VOID NormalRoutine(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	)
{
	UCHAR *ShellCode1 = (UCHAR *)SystemArgument1;
	UCHAR *ShellCode2 = (UCHAR *)SystemArgument2;
	CHAR *DllPath = (CHAR*)NormalContext;										//Dll��·��

	PLDR_DATA_TABLE_ENTRY x;													//�����ҵ������PLDR
	ULONG *NameArry;															//һ����������rva������
	ULONG *AddressArry;															//һ�����溯����ַrva������
	USHORT *OrdinalAddr;														//һ�����溯����ŵ�����
	ULONG i = 0;																//������������ƫ������Rva
	CHAR* FuncNamea;															//�����������
	ULONG_PTR LoadLibraryAddress;
	ULONG_PTR NtdllBase;

	NtdllBase = ((GETLDRLIST)(ShellCode1))();

	x = (PLDR_DATA_TABLE_ENTRY)NtdllBase;
	while (TRUE)
	{
		if (x->BaseDllName.Buffer[0] == L'k' && x->BaseDllName.Buffer[1] == L'e' && x->BaseDllName.Buffer[2] == L'r'
			&& x->BaseDllName.Buffer[3] == L'n' && x->BaseDllName.Buffer[4] == L'e' && x->BaseDllName.Buffer[5] == L'l'
			&& x->BaseDllName.Buffer[6] == L'3' && x->BaseDllName.Buffer[7] == L'2' && x->BaseDllName.Buffer[8] == L'.')
			break;
		x = (PLDR_DATA_TABLE_ENTRY)x->InLoadOrderLinks.Flink;
	}

	NtdllBase = (ULONG_PTR)x->DllBase;
	NtdllBase = (ULONG_PTR)x->DllBase + *(ULONG*)(NtdllBase + 0x3c);						//�����NtdllBase + 0x3cʵ���Ͼ���DosHeader��e_lfanew,������ָ����NtHeader
	NtdllBase = NtdllBase + 0x18;															//ͨ��NtHeader�ҵ�OptionHeader������ֻ�����OptionHeader
	NtdllBase = NtdllBase + 0x70;															//ͨ��OptionHeader�ҵ���DataDirectory�����ָ��DataDirectory
	NtdllBase = (ULONG_PTR)x->DllBase + *(ULONG*)NtdllBase;									//��IMAGE_DATA_DIRECTORY�õ�������
	NameArry = (ULONG*)((ULONG_PTR)x->DllBase + *(ULONG*)(NtdllBase + 0x20));				//�ӵ��������ҵ��������ĵ�ַ���rva + ��ַ��ȡ����������ַ���RVA
	AddressArry = (ULONG*)((ULONG_PTR)x->DllBase + *(ULONG*)(NtdllBase + 0x1c));
	OrdinalAddr = (USHORT*)((ULONG_PTR)x->DllBase + *(ULONG*)(NtdllBase + 0x24));

	while (TRUE)
	{
		if (NameArry[i] != 0)
		{
			FuncNamea = (CHAR*)((ULONG_PTR)x->DllBase + NameArry[i]);
			if (FuncNamea[0] == L'L' && FuncNamea[1] == L'o' && FuncNamea[2] == L'a' && FuncNamea[3] == L'd' && FuncNamea[4] == L'L'
				&& FuncNamea[5] == L'i' &&  FuncNamea[6] == L'b' && FuncNamea[7] == L'r' && FuncNamea[8] == L'a' && FuncNamea[9] == L'r'
				&& FuncNamea[10] == L'y' && FuncNamea[11] == L'A')
			{
				LoadLibraryAddress = AddressArry[i] + (ULONG_PTR)x->DllBase;
				break;
			}
		}
		++i;
	}

	((CALLFUNCTION)(ShellCode2))((ULONG_PTR)DllPath,(ULONG_PTR)LoadLibraryAddress);

	/*//������32λ�Ĵ�����̣����ǻ���ҹؼ����ã�Cȥд�߼��������Ǻ����и����⣬�޷���ô�㣬����ת����shellcode��
	ULONG NtdllBase = 0;														//ǰ�ڵ��м���������ڵ�Kernel��Baseʹ��
	CHAR *DllPath = (CHAR*)NormalContext;										//Dll��·��
	PLDR_DATA_TABLE_ENTRY x;													//�����ҵ������PLDR
	ULONG *NameArry;															//һ����������rva������
	ULONG *AddressArry;															//һ�����溯����ַrva������
	USHORT *OrdinalAddr;														//һ�����溯����ŵ�����
	ULONG i = 0;																//������������ƫ������Rva
	CHAR* FuncNamea;															//�����������
	ULONG LoadLibraryAddress;

	__asm
	{
		pushad;
		pushfd;
		mov eax, fs:[0x30];									//��ȡpeb��ַ
		mov eax, [eax + 0xC];								//��ȡPEB�е�_PEB_LDR_DATA
		mov eax, [eax + 0xC];								//��_PEB_LDR_DATA�л�ȡInLoadOrederModuleList��ÿһ��InLoadOrederModuleListʵ���϶���һ��_LDR_DATA_TABLE_ENTRY
		mov NtdllBase, eax;
		popfd;
		popad;
	}

	x = (PLDR_DATA_TABLE_ENTRY)NtdllBase;

	while (TRUE)
	{
		if (x->BaseDllName.Buffer[0] == L'k' && x->BaseDllName.Buffer[1] == L'e' && x->BaseDllName.Buffer[2] == L'r'
			&& x->BaseDllName.Buffer[3] == L'n' && x->BaseDllName.Buffer[4] == L'e' && x->BaseDllName.Buffer[5] == L'l'
			&& x->BaseDllName.Buffer[6] == L'3' && x->BaseDllName.Buffer[7] == L'2' && x->BaseDllName.Buffer[8] == L'.')
			break;
		x = (PLDR_DATA_TABLE_ENTRY)x->InLoadOrderLinks.Flink;
	}
	NtdllBase = (ULONG)x->DllBase;
	NtdllBase = (ULONG)x->DllBase + *(ULONG*)(NtdllBase + 0x3c);					//�����NtdllBase + 0x3cʵ���Ͼ���DosHeader��e_lfanew,������ָ����NtHeader
	NtdllBase = NtdllBase + 0x18;													//ͨ��NtHeader�ҵ�OptionHeader������ֻ�����OptionHeader
	NtdllBase = NtdllBase + 0x60;													//ͨ��OptionHeader�ҵ���DataDirectory�����ָ��DataDirectory
	NtdllBase = (ULONG)x->DllBase + *(ULONG*)NtdllBase;								//��IMAGE_DATA_DIRECTORY�õ�������
	NameArry = (ULONG*)((ULONG)x->DllBase + *(ULONG*)(NtdllBase + 0x20));			//�ӵ��������ҵ��������ĵ�ַ���rva + ��ַ��ȡ����������ַ���RVA
	AddressArry = (ULONG*)((ULONG)x->DllBase + *(ULONG*)(NtdllBase + 0x1c));
	OrdinalAddr = (USHORT*)((ULONG)x->DllBase + *(ULONG*)(NtdllBase + 0x24));

	while (TRUE)
	{
		if (NameArry[i] != 0)
		{
			FuncNamea = (CHAR*)((ULONG)x->DllBase + NameArry[i]);
			if (FuncNamea[0] == L'L' && FuncNamea[1] == L'o' && FuncNamea[2] == L'a' && FuncNamea[3] == L'd' && FuncNamea[4] == L'L'
				&& FuncNamea[5] == L'i' &&  FuncNamea[6] == L'b' && FuncNamea[7] == L'r' && FuncNamea[8] == L'a' && FuncNamea[9] == L'r'
				&& FuncNamea[10] == L'y' && FuncNamea[11] == L'A')
			{
				LoadLibraryAddress = AddressArry[i] + (ULONG)x->DllBase;
				break;
			}
		}
		++i;
	}

	__asm
	{
		mov ebx, DllPath;
		push ebx;
		mov eax, LoadLibraryAddress;
		call eax;
	}*/

	return;
}

ULONG GetFunctionSizeByAddress(ULONG_PTR FunctionAddress)
{
	ULONG size = 0;
	UCHAR *p;

	if (FunctionAddress == 0)
	{
		KdPrint(("�����ַ����\n"));
		return size;
	}
	if (!MmIsAddressValid((PVOID)FunctionAddress))
	{
		KdPrint(("������ַ���ڴ治�ɶ�ȡ��\n"));
		return size;
	}
	p = (UCHAR*)FunctionAddress;
	while (size < 0x1000)
	{
		if (*p == 0xC3)
		{
			++size;
			break;
		}
		if (*p == 0xC2 && *(p + 1) == 0x0C)
		{
			size = size + 3;
			break;
		}
		++size;
		++p;
	}
	if (size == 0x1000)
	{
		KdPrint(("�ú�����С����ʶ��\n"));
		return 0;
	}
	return size;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	KdPrint(("Unload Success!\n"));
}

/*ԭ���������ý������ң�������Ӳ����̫�鷳�ˣ����ҽ������л��п��ܴ��������Ľ��̣�ֱ��ͨ��ö�ٽ������*/
VOID FindExplore(PKPROCESS* ExploreProcess, PKTHREAD* ExploreThread)
{
	ULONG  i;
	HANDLE ProcessHandle;
	PEPROCESS TempProcess;															//����ö��ʹ�õĽ��̶���
	PETHREAD TempThread;															//����ö��ʹ�õ��̶߳���
	ULONG_PTR BoolAlterable;														//�жϵ�ǰ�߳��Ƿ�Ϊ�ɻ���״̬
	ULONG_PTR BoolQueueable;														//�жϵ�ǰ�߳��Ƿ��ڿ��Բ���APC��״̬

	for (i = 8; i < 0x40000; i += 4)												//���������׵ķ�������512*1024*1024�����ǣ�0x40000һ�㶼�ò��ϣ�����512*1024*1024��0x40000�����ࣨ��0��ʼ��������ms����0�Ž��������⣩
	{
		PsLookupThreadByThreadId((HANDLE)i, &TempThread);
		if (TempThread == NULL)
			continue;
#if NTDDI_VERSION >= NTDDI_VISTA
		ProcessHandle = (HANDLE)PsGetThreadProcessId(TempThread);
#else
		ProcessHandle = (HANDLE)(*(ULONG*)((UCHAR*)TempThread + 0x1ec));
#endif
		if (ProcessHandle == NULL)
		{
			sfObDereferenceObject(TempThread);
			continue;
		}
		PsLookupProcessByProcessId(ProcessHandle, &TempProcess);
		if (TempProcess == NULL)															//�ж��»�ȡ�Ľ��̾����û�п��ܲ�����
		{
			sfObDereferenceObject(TempThread);
			continue;
		}
		if (!strstr((UCHAR*)TempProcess + NameOffset, "explorer"/*"TestCPP"*/))				//������Ҫ�Ľ����������ü���ѭ��
		{
			sfObDereferenceObject(TempProcess);
			sfObDereferenceObject(TempThread);
			continue;
		}
		else
		{
#ifdef _WIN64																				//�������*64����
			BoolAlterable = JudgeAlertable((ULONG_PTR)TempThread);
			BoolQueueable = JudgeQueueable((ULONG_PTR)TempThread);
#else
#if NTDDI_VERSION >= NTDDI_VISTA
			__asm
			{
				push eax;
				push ebx;
				mov eax, TempThread;
				mov eax, dword ptr[eax + 3Ch];
				mov ebx, 0x20;
				and eax, ebx;
				mov BoolAlterable, eax;
				pop ebx;
				pop eax;
			}																				//�ж��߳�״̬�ǲ��ǳ��ڿɻ���״̬
			__asm
			{
				push eax;
				push ebx;
				mov eax, TempThread;
				mov eax, dword ptr[eax + 0xb8];
				mov ebx, 0x20;
				and eax, ebx;
				mov BoolQueueable, eax;
				pop ebx;
				pop eax;
			}
#else
			__asm
			{
				push eax;
				push ebx;
				mov eax, TempThread;
				mov al, byte ptr[eax + 0x164];
				mov ebx, 1;
				and eax, ebx;
				mov BoolAlterable, eax;
				pop ebx;
				pop eax;
			}
			__asm
			{
				push eax;
				push ebx;
				mov eax, TempThread;
				mov al, byte ptr[eax + 0x166];
				mov ebx, 1;
				and eax, ebx;
				mov BoolQueueable, eax;
				pop ebx;
				pop eax;
			}
#endif
#endif
			if (!BoolAlterable || !BoolQueueable)
			{
				sfObDereferenceObject(TempProcess);
				sfObDereferenceObject(TempThread);
				continue;
			}
		}

		*ExploreProcess = (PKPROCESS)TempProcess;
		*ExploreThread = (PKTHREAD)TempThread;
		break;
	}
	KdPrint(("Process Name is %s\n", (UCHAR*)TempProcess + NameOffset));
	return;
}

VOID Run()
{
	PKPROCESS ExplorerProcess;														//Explorer�Ľ��̶���
	PKTHREAD ExplorerThread;														//Explorer���̶߳���
	HANDLE ExplorerHandle;															//Explorer�ľ��
	PVOID IsWOW64Process = (PVOID)1;												//�����ж��Ƿ���������64λϵͳ�ϵ�*86����
	NTSTATUS status;
	KAPC_STATE apc;																				//�����ҿ�ʹ��
	PKAPC MyApc;

	PVOID PathBuffer = NULL;
	PVOID FuncBuffer = NULL;
	PVOID Code1Buffer = NULL;
	PVOID Code2Buffer = NULL;
	CHAR DllPath[] = "C:\\MyDLL.dll";
	SSIZE_T AllocateSize = sizeof(DllPath);														//��DLL����Ŀռ��С
	SSIZE_T FunctionSize = sizeof(NormalCode) > GetFunctionSizeByAddress((ULONG_PTR)NormalRoutine) ?
		sizeof(NormalCode) : GetFunctionSizeByAddress((ULONG_PTR)NormalRoutine);				//���ʱ����ȷ���ǵ����ĸ����������ȡ���ֵ���˷��ڴ��ֻ���˷���          
	SSIZE_T SizeCode1 = sizeof(GetLdrList);
	SSIZE_T SizeCode2 = sizeof(CallFunction);

	MyApc = (PKAPC)sfExAllocatePool(sizeof(KAPC));

	sfCheckMemory(MyApc);

	FindExplore(&ExplorerProcess, &ExplorerThread);												//��Ѱ��Explorer�Ľ��̺��̶߳���

	status = ObOpenObjectByPointer(ExplorerProcess, OBJ_KERNEL_HANDLE, NULL, GENERIC_ALL, *PsProcessType, KernelMode, &ExplorerHandle);
	if (FailStatus(status))
	{
		KdPrint(("OpenProcess Faile!,status is %x\n", status));
		return;
	}

	status = ZwAllocateVirtualMemory(ExplorerHandle, &PathBuffer, 0, (SIZE_T *)&AllocateSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (FailStatus(status))
	{
		KdPrint(("AllocateMemory Faile!,status is %x\n", status));
		return;
	}

	status = ZwAllocateVirtualMemory(ExplorerHandle, &FuncBuffer, 0, (SIZE_T *)&FunctionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (FailStatus(status))
	{
		KdPrint(("AllocateMemory Faile!,status is %x\n", status));
		return;
	}

#ifdef _WIN64	
	IsWOW64Process = (PVOID)(*(ULONG_PTR*)((UCHAR*)ExplorerProcess + 0x320));								//�õ�Eprocess�е�Wow64Process��������Ԫ��ΪNULL��֤����һ����64λ���̣��������һ��Wow64Process

	if (IsWOW64Process == NULL)
	{
		status = ZwAllocateVirtualMemory(ExplorerHandle, &Code1Buffer, 0, (SIZE_T *)&SizeCode1, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (FailStatus(status))
		{
			KdPrint(("AllocateMemory Faile!,status is %x\n", status));
			return;
		}

		status = ZwAllocateVirtualMemory(ExplorerHandle, &Code2Buffer, 0, (SIZE_T *)&SizeCode2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (FailStatus(status))
		{
			KdPrint(("AllocateMemory Faile!,status is %x\n", status));
			return;
		}
	}
#endif

	KeStackAttachProcess(ExplorerProcess, &apc);

	RtlZeroMemory(PathBuffer, AllocateSize);
	RtlZeroMemory(FuncBuffer, FunctionSize);
	AllocateSize = sizeof(DllPath);
	RtlCopyMemory(PathBuffer, DllPath, AllocateSize);

	if (IsWOW64Process == NULL)
	{
		RtlZeroMemory(Code1Buffer, SizeCode1);
		RtlZeroMemory(Code2Buffer, SizeCode2);
		SizeCode1 = sizeof(GetLdrList);
		SizeCode2 = sizeof(CallFunction);
		RtlCopyMemory(Code1Buffer, GetLdrList, SizeCode1);
		RtlCopyMemory(Code2Buffer, CallFunction, SizeCode2);

		FunctionSize = GetFunctionSizeByAddress((ULONG_PTR)NormalRoutine);
		RtlCopyMemory(FuncBuffer, (PVOID)((ULONG_PTR)NormalRoutine + 0xF), FunctionSize - 0xF);					//Debugģʽ�µĺ�����Ѳ������浽��ջ��һ���������������ᣬ������һ�±��������ѱ����������������
	}
	else
	{
		FunctionSize = sizeof(NormalCode);
		RtlCopyMemory(FuncBuffer, (PVOID)((ULONG_PTR)NormalCode), FunctionSize);
		if (IsWOW64Process != (PVOID)1)																			//�����жϵľ�����������������*86ϵͳ�ϵĽ��̻���*64ϵͳ�����е�*86����
			FuncBuffer = (PVOID)((~(ULONG_PTR)(FuncBuffer)+1) << 2);

	}
	KeUnstackDetachProcess(&apc);

	KeInitializeApc(MyApc, ExplorerThread, OriginalApcEnvironment, KernelRoutine, NULL, (PKNORMAL_ROUTINE)FuncBuffer, UserMode, PathBuffer);
	
	if (IsWOW64Process == NULL)
		status = KeInsertQueueApc(MyApc, Code1Buffer, Code2Buffer, 0);
	else
		status = KeInsertQueueApc(MyApc, NULL, NULL, 0);

	if (!status)
	{
		KdPrint(("Inser APC Fail!\n"));
		return;
	}

	sfObDereferenceObject(ExplorerProcess);
	sfObDereferenceObject(ExplorerThread);
}

VOID Init(PDRIVER_OBJECT DriverObject)
{
	CHAR *t = (CHAR*)PsGetCurrentProcess();
	ULONG i = 0;

	UNICODE_STRING nKeInitializeApc;												//KeInitializeApc����������
	UNICODE_STRING nKeInsertQueueApc;												//KeInsertQueueApc����������

	KdPrint(("Entry Driver!\n"));

	while (i < 0x300)
	{
		if (*t == 'S' && *(t + 1) == 'y' && *(t + 2) == 's' && *(t + 3) == 't' && *(t + 4) == 'e' && *(t + 5) == 'm')
		{
			NameOffset = i;
			break;
		}
		++i;
		++t;
	}

	RtlInitUnicodeString(&nKeInitializeApc, L"KeInitializeApc");
	RtlInitUnicodeString(&nKeInsertQueueApc, L"KeInsertQueueApc");

	KeInitializeApc = (KEINITIALIZEAPC)MmGetSystemRoutineAddress(&nKeInitializeApc);
	KeInsertQueueApc = (KEINSERTQUEUEAPC)MmGetSystemRoutineAddress(&nKeInsertQueueApc);

	Run();

	DriverObject->DriverUnload = Unload;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegString)
{
	UNREFERENCED_PARAMETER(RegString);
	Init(DriverObject);
	return STATUS_SUCCESS;
}