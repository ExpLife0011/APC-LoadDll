#include "x.h"

ULONG NameOffset;													//EPROCESS中名字的偏移值
KEINITIALIZEAPC KeInitializeApc;									//用来初始化APC的函数
KEINSERTQUEUEAPC KeInsertQueueApc;									//用来把APC插入到对应线程的函数

ULONG_PTR JudgeAlertable(ULONG_PTR ThreadAddress)
{
	UCHAR *FuncMemory;
	ULONG_PTR RetValue;
	FuncMemory = sfExAllocatePool(sizeof(AlertableCode));
	if (FuncMemory == NULL)
	{
		KdPrint(("分配内存失败！\n"));
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
		KdPrint(("分配内存失败！\n"));
		return 0;
	}
	RtlCopyMemory(FuncMemory, QueueableCode, sizeof(QueueableCode));
	RetValue = ((JUDGEQUEUEABLE)(FuncMemory))(ThreadAddress);
	sfExFreePool(FuncMemory);
	return RetValue;
}

VOID KernelRoutine(__in KAPC *Apc,									//单纯的释放一下APC对象，因为目标是注入DLL所以要去使用USER_MODE APC
	__deref_inout_opt PKNORMAL_ROUTINE *NormalRoutine,				//这个参数实际上就是初始化APC的时候传入的NormalRoutine，所以才有（可以在KernelRoutinue中清空NormalRoutinue这句话）
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
	CHAR *DllPath = (CHAR*)NormalContext;										//Dll的路径

	PLDR_DATA_TABLE_ENTRY x;													//用来找到具体的PLDR
	ULONG *NameArry;															//一个保存名字rva的数组
	ULONG *AddressArry;															//一个保存函数地址rva的数组
	USHORT *OrdinalAddr;														//一个保存函数标号的数组
	ULONG i = 0;																//用来记下名字偏移量的Rva
	CHAR* FuncNamea;															//输出函数名字
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
	NtdllBase = (ULONG_PTR)x->DllBase + *(ULONG*)(NtdllBase + 0x3c);						//这里的NtdllBase + 0x3c实际上就是DosHeader的e_lfanew,现如今就指向了NtHeader
	NtdllBase = NtdllBase + 0x18;															//通过NtHeader找到OptionHeader，现在只想的是OptionHeader
	NtdllBase = NtdllBase + 0x70;															//通过OptionHeader找到了DataDirectory，如今指向DataDirectory
	NtdllBase = (ULONG_PTR)x->DllBase + *(ULONG*)NtdllBase;									//从IMAGE_DATA_DIRECTORY拿到导出表
	NameArry = (ULONG*)((ULONG_PTR)x->DllBase + *(ULONG*)(NtdllBase + 0x20));				//从导出表中找到函数名的地址表的rva + 基址获取到函数名地址表的RVA
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

	/*//这里是32位的处理过程，就是汇编找关键调用，C去写逻辑处理，但是后来有个问题，无法这么搞，还是转化成shellcode了
	ULONG NtdllBase = 0;														//前期当中间变量，后期当Kernel的Base使用
	CHAR *DllPath = (CHAR*)NormalContext;										//Dll的路径
	PLDR_DATA_TABLE_ENTRY x;													//用来找到具体的PLDR
	ULONG *NameArry;															//一个保存名字rva的数组
	ULONG *AddressArry;															//一个保存函数地址rva的数组
	USHORT *OrdinalAddr;														//一个保存函数标号的数组
	ULONG i = 0;																//用来记下名字偏移量的Rva
	CHAR* FuncNamea;															//输出函数名字
	ULONG LoadLibraryAddress;

	__asm
	{
		pushad;
		pushfd;
		mov eax, fs:[0x30];									//获取peb基址
		mov eax, [eax + 0xC];								//获取PEB中的_PEB_LDR_DATA
		mov eax, [eax + 0xC];								//从_PEB_LDR_DATA中获取InLoadOrederModuleList，每一项InLoadOrederModuleList实际上都是一个_LDR_DATA_TABLE_ENTRY
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
	NtdllBase = (ULONG)x->DllBase + *(ULONG*)(NtdllBase + 0x3c);					//这里的NtdllBase + 0x3c实际上就是DosHeader的e_lfanew,现如今就指向了NtHeader
	NtdllBase = NtdllBase + 0x18;													//通过NtHeader找到OptionHeader，现在只想的是OptionHeader
	NtdllBase = NtdllBase + 0x60;													//通过OptionHeader找到了DataDirectory，如今指向DataDirectory
	NtdllBase = (ULONG)x->DllBase + *(ULONG*)NtdllBase;								//从IMAGE_DATA_DIRECTORY拿到导出表
	NameArry = (ULONG*)((ULONG)x->DllBase + *(ULONG*)(NtdllBase + 0x20));			//从导出表中找到函数名的地址表的rva + 基址获取到函数名地址表的RVA
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
		KdPrint(("传入地址错误！\n"));
		return size;
	}
	if (!MmIsAddressValid((PVOID)FunctionAddress))
	{
		KdPrint(("函数地址上内存不可读取！\n"));
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
		KdPrint(("该函数大小不可识别！\n"));
		return 0;
	}
	return size;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	KdPrint(("Unload Success!\n"));
}

/*原本这里想用进程链找，但是找硬编码太麻烦了，而且进程链中还有可能存在死亡的进程，直接通过枚举解决好了*/
VOID FindExplore(PKPROCESS* ExploreProcess, PKTHREAD* ExploreThread)
{
	ULONG  i;
	HANDLE ProcessHandle;
	PEPROCESS TempProcess;															//用来枚举使用的进程对象
	PETHREAD TempThread;															//用来枚举使用的线程对象
	ULONG_PTR BoolAlterable;														//判断当前线程是否为可唤醒状态
	ULONG_PTR BoolQueueable;														//判断当前线程是否处于可以插入APC的状态

	for (i = 8; i < 0x40000; i += 4)												//这里最稳妥的方法是用512*1024*1024，但是，0x40000一般都用不上，况且512*1024*1024比0x40000字数多（从0开始会蓝屏，ms处理0号进程有问题）
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
		if (TempProcess == NULL)															//判断下获取的进程句柄有没有可能不存在
		{
			sfObDereferenceObject(TempThread);
			continue;
		}
		if (!strstr((UCHAR*)TempProcess + NameOffset, "explorer"/*"TestCPP"*/))				//不是想要的进程则解除引用继续循环
		{
			sfObDereferenceObject(TempProcess);
			sfObDereferenceObject(TempThread);
			continue;
		}
		else
		{
#ifdef _WIN64																				//如果处于*64程序
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
			}																				//判断线程状态是不是出于可唤醒状态
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
	PKPROCESS ExplorerProcess;														//Explorer的进程对象
	PKTHREAD ExplorerThread;														//Explorer的线程对象
	HANDLE ExplorerHandle;															//Explorer的句柄
	PVOID IsWOW64Process = (PVOID)1;												//用来判断是否是运行在64位系统上的*86程序
	NTSTATUS status;
	KAPC_STATE apc;																				//用来挂靠使用
	PKAPC MyApc;

	PVOID PathBuffer = NULL;
	PVOID FuncBuffer = NULL;
	PVOID Code1Buffer = NULL;
	PVOID Code2Buffer = NULL;
	CHAR DllPath[] = "C:\\MyDLL.dll";
	SSIZE_T AllocateSize = sizeof(DllPath);														//给DLL分配的空间大小
	SSIZE_T FunctionSize = sizeof(NormalCode) > GetFunctionSizeByAddress((ULONG_PTR)NormalRoutine) ?
		sizeof(NormalCode) : GetFunctionSizeByAddress((ULONG_PTR)NormalRoutine);				//这个时候不能确定是调用哪个函数，因此取最大值，浪费内存就只能浪费了          
	SSIZE_T SizeCode1 = sizeof(GetLdrList);
	SSIZE_T SizeCode2 = sizeof(CallFunction);

	MyApc = (PKAPC)sfExAllocatePool(sizeof(KAPC));

	sfCheckMemory(MyApc);

	FindExplore(&ExplorerProcess, &ExplorerThread);												//搜寻到Explorer的进程和线程对象

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
	IsWOW64Process = (PVOID)(*(ULONG_PTR*)((UCHAR*)ExplorerProcess + 0x320));								//得到Eprocess中的Wow64Process，如果这个元素为NULL则证明是一个纯64位进程，否则存在一个Wow64Process

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
		RtlCopyMemory(FuncBuffer, (PVOID)((ULONG_PTR)NormalRoutine + 0xF), FunctionSize - 0xF);					//Debug模式下的函数会把参数保存到堆栈，一共是三条语句很讨厌，这里逆一下编译器，把保存参数的语句给过掉
	}
	else
	{
		FunctionSize = sizeof(NormalCode);
		RtlCopyMemory(FuncBuffer, (PVOID)((ULONG_PTR)NormalCode), FunctionSize);
		if (IsWOW64Process != (PVOID)1)																			//这里判断的就是这个进程是真的是*86系统上的进程还是*64系统上运行的*86进程
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

	UNICODE_STRING nKeInitializeApc;												//KeInitializeApc函数的名字
	UNICODE_STRING nKeInsertQueueApc;												//KeInsertQueueApc函数的名字

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