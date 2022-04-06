// ImportAdder.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <string>
using namespace std;
/*
Add a new section to gain space for additional imports
Copy the old IMAGE_IMPORT_DESCRIPTOR array to the new section
Point the import entry in the IMAGE_DATA_DIRECTORY array to the new position of the IMAGE_IMPORT_DSCRIPTOR array and adjust the size.
Add the new imports
Add the module/DLL name
Add the IMPORT_BY_NAME array, e.g. the functions to import from the module/DLL
Add the IMAGE_THUNK_DATA arrays which point to the IMPORT_BY_NAME structures.
Add an IMAGE_IMPORT_DESCRIPTOR where the Name entry points to the name we added and the FirstThunk to the IMAGE_THUNK_DATA array we added.
*/

/*
   pNewPE          :新PE文件的内存首地址
   pOldImports     :原有PE文件中的导入表描述符首地址
   dwOldImportSize :原有PE文件中的导入表描述符的大小
   dwFVA           :新PE文件导入表要写入的文件偏移
   dwRVA           :新PE文件导入表要写入的虚拟地址偏移
*/
VOID CopyAndSetImportDesData(PUCHAR pNewPE, PUCHAR pOldImports,DWORD dwOldImportSize, DWORD dwFVA, DWORD dwRVA,PCHAR pDllName,PCHAR pFunctioName)
{
	//DWORD dwOldImportSize = sizeof(IMAGE_IMPORT_DESCRIPTOR) * dwImportDllsCount;
	//拷贝原有的导入表至新的区段
	memcpy(pNewPE + dwFVA, pOldImports, dwOldImportSize);

	//根据旧的导入表，写入一个新的导入表至新的区段
	memcpy(pNewPE + dwFVA + dwOldImportSize, pOldImports, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	//添加导入表结尾
	memset(pNewPE + dwFVA + dwOldImportSize + sizeof(IMAGE_IMPORT_DESCRIPTOR), 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));

	//
	//在新的区段中重新建立导入表的描述，不在旧的区段中是因为要新增导入表描述符，怕旧的区段空间不够用
	//修正新区段中IMAGE_IMPORT_DESCRIPTOR的RAV
	PIMAGE_IMPORT_DESCRIPTOR pNewImport = (PIMAGE_IMPORT_DESCRIPTOR)(pNewPE + dwFVA + dwOldImportSize);

	//FirstThunk的位置写在导入表描述符最后一个元素后再偏移3*sizeof(IMAGE_IMPORT_DESCRIPTOR)位置处
	DWORD dwFirstThunkOffset = dwOldImportSize + sizeof(IMAGE_IMPORT_DESCRIPTOR) *  3;

	//dll的名字，写在FirstThunk+ sizeof(DWORD_PTR)*2 的位置
	DWORD dwDllNameOffset = dwFirstThunkOffset + sizeof(DWORD_PTR) * 2;

	pNewImport->Name = dwRVA /*内存偏移*/ + dwDllNameOffset;

	//OriginalFirstThunk 和FirstThunk 设置为相同地址，这个地址也是个内存偏移，记录的是IMPORT_BY_NAME的地址
	pNewImport->FirstThunk = pNewImport->OriginalFirstThunk = dwRVA  /*内存偏移*/ + dwFirstThunkOffset;

	//根据文件偏移计算实际的文件地址，写入dll名字
	memcpy(pNewPE + dwFVA + dwDllNameOffset, pDllName, strlen(pDllName));

	//写完dll名字，+1的地址写入IMPORT_BY_NAME的结构体数据
	DWORD dwImportByNameOffset = dwDllNameOffset + strlen(pDllName) + 1;

	do
	{
		PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
		pImportByName = (PIMAGE_IMPORT_BY_NAME)malloc(40);
		memset(pImportByName, 0, 40);
		pImportByName->Hint = 1;
		memcpy(pImportByName->Name, pFunctioName, strlen(pFunctioName));
		memcpy(pNewPE + dwFVA + dwImportByNameOffset, pImportByName, 40);
		free(pImportByName);
	} while (false);

	DWORD dwFirstThunkVA = (DWORD)(dwRVA + dwImportByNameOffset);
	//写入FirstThunk的内存偏移地址，里面村的是IMPORT_BY_NAME的内存偏移
	memcpy(pNewPE + dwFVA + dwFirstThunkOffset, &dwFirstThunkVA, 4);
}

PVOID SetPointer(PVOID pBase, DWORD space)
{
	if (!pBase) return NULL;

	return PVOID((DWORD)pBase + space);
}

 /************************************************************************/
/*
功能:虚拟内存相对地址和文件偏移的转换
参数：stRVA：    虚拟内存相对偏移地址
	  lpFileBuf: 文件起始地址
返回：转换后的文件偏移地址
*/
/************************************************************************/
size_t RVAToOffset(size_t stRVA, PVOID lpFileBuf)
{
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpFileBuf;
	size_t stPEHeadAddr = (size_t)lpFileBuf + pDos->e_lfanew;
	PIMAGE_NT_HEADERS32 pNT = (PIMAGE_NT_HEADERS32)stPEHeadAddr;
	//区段数
	DWORD dwSectionCount = pNT->FileHeader.NumberOfSections;
	//内存对齐大小
	DWORD dwMemoruAil = pNT->OptionalHeader.SectionAlignment;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNT);
	//距离命中节的起始虚拟地址的偏移值。
	DWORD  dwDiffer = 0;
	for (DWORD i = 0; i < dwSectionCount; i++)
	{
		//模拟内存对齐机制
		DWORD dwBlockCount = pSection[i].SizeOfRawData / dwMemoruAil;
		dwBlockCount += pSection[i].SizeOfRawData % dwMemoruAil ? 1 : 0;

		DWORD dwBeginVA = pSection[i].VirtualAddress;
		DWORD dwEndVA = pSection[i].VirtualAddress + dwBlockCount * dwMemoruAil;
		//如果stRVA在某个区段中
		if (stRVA >= dwBeginVA && stRVA < dwEndVA)
		{
			dwDiffer = stRVA - dwBeginVA;
			return pSection[i].PointerToRawData + dwDiffer;
		}
		else if (stRVA < dwBeginVA)//在文件头中直接返回
		{
			return stRVA;
		}
	}
	return 0;
}
/************************************************************************/
/*
功能：文件偏移地址和虚拟地址的转换
参数：stOffset：文件偏移地址
	  lpFileBuf:虚拟内存起始地址
返回：转换后的虚拟地址
*/
/************************************************************************/
size_t Offset2VA(size_t stOffset, PVOID lpFileBuf)
{
	//获取DOS头
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)lpFileBuf;
	//获取PE头
	//e_lfanew:PE头相对于文件的偏移地址
	size_t stPEHeadAddr = (size_t)lpFileBuf + pDos->e_lfanew;
	PIMAGE_NT_HEADERS32 pNT = (PIMAGE_NT_HEADERS32)stPEHeadAddr;
	//区段数
	DWORD dwSectionCount = pNT->FileHeader.NumberOfSections;
	//映像地址
	DWORD dwImageBase = pNT->OptionalHeader.ImageBase;
	//区段头
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNT);

	//相对大小
	DWORD  dwDiffer = 0;
	for (DWORD i = 0; i < dwSectionCount; i++)
	{
		//区段的起始地址和结束地址
		DWORD dwBeginVA = pSection[i].PointerToRawData;
		DWORD dwEndVA = pSection[i].PointerToRawData + pSection[i].SizeOfRawData;
		//如果文件偏移地址在dwBeginVA和dwEndVA之间
		if (stOffset >= dwBeginVA && stOffset < dwEndVA)
		{
			//相对大小
			dwDiffer = stOffset - dwBeginVA;
			//进程的起始地址 + 区段的相对地址 + 相对区段的大小
			return  pSection[i].VirtualAddress + dwDiffer;
		}
		else if (stOffset < dwBeginVA)    //如果文件偏移地址不在区段中
		{
			return  stOffset;
		}
	}
	return 0;
}



DWORD Align(IN DWORD dwAlign, IN DWORD dwVar)
{
	//小于等于对齐直接返回当前对齐
	if (dwVar <= dwAlign)
	{
		return dwAlign;
	}

	//如果可以整除处理
	if (dwVar % dwAlign == 0)
	{
		return dwVar;
	}

	//大于对齐且不能被整除处理
	return dwAlign * (dwVar / dwAlign + 1);

}
PVOID FileToMem(IN PCHAR szFilePath, OUT LPDWORD dwFileSize)
{
	//打开文件
	FILE* pFile = NULL;
	fopen_s(&pFile,szFilePath, "rb");
	if (!pFile)
	{
		printf("FileToMem fopen Fail \r\n");
		return NULL;
	}

	//获取文件长度
	fseek(pFile, 0, SEEK_END);			//SEEK_END文件结尾
	DWORD Size = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);			//SEEK_SET文件开头

	//申请存储文件数据缓冲区
	PCHAR pFileBuffer = (PCHAR)malloc(Size);
	if (!pFileBuffer)
	{
		printf("FileToMem malloc Fail \r\n");
		fclose(pFile);
		return NULL;
	}

	//读取文件数据
	fread(pFileBuffer, Size, 1, pFile);

	//判断是否为可执行文件
	if (*(PSHORT)pFileBuffer != IMAGE_DOS_SIGNATURE)
	{
		printf("Error: MZ \r\n");
		fclose(pFile);
		free(pFileBuffer);
		return NULL;
	}

	if (*(PDWORD)(pFileBuffer + *(PDWORD)(pFileBuffer + 0x3C)) != IMAGE_NT_SIGNATURE)
	{
		printf("Error: PE \r\n");
		fclose(pFile);
		free(pFileBuffer);
		return NULL;
	}

	if (dwFileSize)
	{
		*dwFileSize = Size;
	}

	fclose(pFile);

	return pFileBuffer;
}

BOOL MoveNtAndSectionToDosStub(IN PCHAR pRawData)
{
	//定位结构
	PIMAGE_DOS_HEADER        pDos = (PIMAGE_DOS_HEADER)pRawData;
	PIMAGE_NT_HEADERS        pNth = (PIMAGE_NT_HEADERS)(pRawData + pDos->e_lfanew);
	PIMAGE_FILE_HEADER		 pFil = (PIMAGE_FILE_HEADER)((PUCHAR)pNth + 4);
	PIMAGE_OPTIONAL_HEADER   pOpo = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFil + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER    pSec = (PIMAGE_SECTION_HEADER)((PUCHAR)pOpo + pFil->SizeOfOptionalHeader);

	//清空DOS_STUB数据
	memset(pRawData + sizeof(IMAGE_DOS_HEADER), 0, pDos->e_lfanew - sizeof(IMAGE_DOS_HEADER));

	//移动数据大小
	DWORD dwMoveSize = sizeof(IMAGE_NT_HEADERS) + pFil->NumberOfSections * IMAGE_SIZEOF_SECTION_HEADER;

	//备份数据
	PUCHAR pNewPE = (PUCHAR)malloc(dwMoveSize);
	if (!pNewPE)
	{
		return FALSE;
	}
	memset(pNewPE, 0, dwMoveSize);
	memcpy(pNewPE, pRawData + pDos->e_lfanew, dwMoveSize);

	//清空默认数据
	memset(pRawData + pDos->e_lfanew, 0, dwMoveSize);

	//移动数据
	memcpy(pRawData + sizeof(IMAGE_DOS_HEADER), pNewPE, dwMoveSize);

	//修正e_lfanew指向
	pDos->e_lfanew = sizeof(IMAGE_DOS_HEADER);

	free(pNewPE);

	return TRUE;
}

VOID BuildNewImportDes(IMAGE_SECTION_HEADER &pNewImport,DWORD dwFileAlignment,DWORD dwSectionRawSize,DWORD dwFVA/*文件偏移*/)
{
	//填充新增节数据
	CHAR szName[] = ".Ker";
	memcpy((PVOID)pNewImport.Name, szName, strlen(szName));
	pNewImport.Misc.VirtualSize = 0x1000;//内存中对齐前的大小
	pNewImport.SizeOfRawData = Align(dwFileAlignment, dwSectionRawSize);//文件中对齐后的大小
	pNewImport.PointerToRawData = Align(dwFileAlignment, dwFVA);//文件中的偏移
	pNewImport.PointerToRelocations = 0;
	pNewImport.PointerToLinenumbers = 0;
	pNewImport.NumberOfRelocations = 0;
	pNewImport.NumberOfLinenumbers = 0;
	pNewImport.Characteristics = 0xC0000040;//默认代
}


PVOID AddNewSection(PCHAR pRawData, DWORD dwSectionSize, LPDWORD pNewFileSize,PCHAR pDllName,PCHAR pFunctioName)
{
	if (!pRawData || !pDllName || !pFunctioName) return NULL;
	//定位结构
	PIMAGE_DOS_HEADER        pDos = (PIMAGE_DOS_HEADER)pRawData;
	PIMAGE_NT_HEADERS        pNth = (PIMAGE_NT_HEADERS)(pRawData + pDos->e_lfanew);
	PIMAGE_FILE_HEADER		 pFil = (PIMAGE_FILE_HEADER)((PUCHAR)pNth + 4);
	PIMAGE_OPTIONAL_HEADER   pOpo = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFil + IMAGE_SIZEOF_FILE_HEADER);
	PIMAGE_SECTION_HEADER    pSec = (PIMAGE_SECTION_HEADER)((PUCHAR)pOpo + pFil->SizeOfOptionalHeader);
	PIMAGE_IMPORT_DESCRIPTOR pImports = (PIMAGE_IMPORT_DESCRIPTOR)(pRawData + RVAToOffset(pOpo->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, pRawData));
  	pOpo->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
 	PIMAGE_IMPORT_DESCRIPTOR pNewPEImports = pImports;
	printf("import tableRva:%p\n", pImports);

	//获取导入表的个数(dll的个数）
	DWORD dwImportDllsCount = 0;
	for (;pNewPEImports->Name;++pNewPEImports)
	{
		dwImportDllsCount++;
	}
	printf("import table count:%d\n", dwImportDllsCount);


	//判断头部是否有空间新增节
	if ((DWORD)(pRawData + pOpo->SizeOfHeaders - (DWORD)&pSec[pFil->NumberOfSections + 1]) < IMAGE_SIZEOF_SECTION_HEADER)
	{
		//抹除DOS_STUB数据并将NT,SECTION整理向上移动
		BOOL bRet = MoveNtAndSectionToDosStub(pRawData);
		if (!bRet)
		{
			printf("AddNewSection MoveNtAndSectionToDosStub Fail \r\n");
			free(pRawData);
			return NULL;
		}

		pDos = (PIMAGE_DOS_HEADER)pRawData;
		pNth = (PIMAGE_NT_HEADERS)(pRawData + pDos->e_lfanew);
		pFil = (PIMAGE_FILE_HEADER)((PUCHAR)pNth + 4);
		pOpo = (PIMAGE_OPTIONAL_HEADER)((PUCHAR)pFil + IMAGE_SIZEOF_FILE_HEADER);
		pSec = (PIMAGE_SECTION_HEADER)((PUCHAR)pOpo + pFil->SizeOfOptionalHeader);
	}

	//填充新增节数据
	DWORD dwOldLastSecIndex = pFil->NumberOfSections - 1;
	DWORD dwNewSecIndex = pFil->NumberOfSections;
	DWORD dwFVA = pSec[dwOldLastSecIndex].PointerToRawData + pSec[dwOldLastSecIndex].SizeOfRawData;
	BuildNewImportDes(pSec[dwNewSecIndex], pOpo->FileAlignment, dwSectionSize, dwFVA);
	
	//设置代码段Characteristics
	pSec[0].Characteristics = 0xC0000040;

	//对旧文件中最后一个section做修正
	DWORD dwOldSize = 0;
	DWORD dwNewSize = 0;
	do
	{
		//计算旧文件最后一个section末尾得文件偏移地址
		DWORD dwOldSectionEndFVA = pSec[dwOldLastSecIndex].PointerToRawData + pSec[dwOldLastSecIndex].SizeOfRawData;

		//计算旧的最后一个section要被扩展的空间大小
		DWORD dwLastSectionExtern = pSec[dwNewSecIndex].PointerToRawData - dwOldSectionEndFVA;


		//对旧的最后一个section的大小做二次修正
		dwOldSize = pSec[dwOldLastSecIndex].SizeOfRawData + pSec[dwOldLastSecIndex].PointerToRawData;
		pSec[dwOldLastSecIndex].SizeOfRawData += dwLastSectionExtern;
		pSec[dwOldLastSecIndex].Misc.VirtualSize = pSec[dwOldLastSecIndex].SizeOfRawData; //仿照STUDY_PE获得
	} while (false);
	//计算PE文件中额外数据得大小和文件偏移
	DWORD dwExtraDataSize = *(DWORD*)pNewFileSize - dwOldSize;
	PVOID pExtraDataFVA = pRawData + dwOldSize;


	//重新计算新增区段的内存偏移地址
	pSec[dwNewSecIndex].VirtualAddress = Align(pOpo->SectionAlignment, pSec[dwOldLastSecIndex].Misc.VirtualSize + pSec[dwOldLastSecIndex].VirtualAddress);//内存中的偏移

	// Set the import data directory to the new import section and adjust the size
	pOpo->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pSec[dwNewSecIndex].VirtualAddress;
	DWORD RvaOff = pOpo->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	DWORD FvaOff = pSec[dwNewSecIndex].PointerToRawData;

    //修复内存镜像大小
	pOpo->SizeOfImage = Align(pSec[dwNewSecIndex].VirtualAddress + pSec[dwNewSecIndex].Misc.VirtualSize, 0x1000);
	//
	//新增节后补充大小为IMAGE_SECTION_HEADER结构的0数据
	memset(&pSec[dwNewSecIndex + 1], 0, IMAGE_SIZEOF_SECTION_HEADER);
	//修复默认节数量
	pFil->NumberOfSections++;

	//当前文件大小
	dwNewSize = pSec[dwNewSecIndex].SizeOfRawData + pSec[dwNewSecIndex].PointerToRawData ;
	if (pNewFileSize)
	{
		*pNewFileSize = dwNewSize + dwExtraDataSize;
	}

	//重新分配缓冲区
	PUCHAR pNewPE = (PUCHAR)malloc(*pNewFileSize);
	if (!pNewPE)
	{
		printf("AddNewSection malloc Fail \r\n");
		free(pRawData);
		return NULL;
	}
	memset(pNewPE, 0, *pNewFileSize);

	//将旧文件的格式拷贝到新的PE中
	memcpy(pNewPE, pRawData, dwOldSize);
	
	//
	//按下面格式拷贝
	///2*sizeof(IMAGE_IMPORT_DESCRIPTOR)   FirstThunkRVA + sizeof(DWORD)+DllNameRVA + IMPORT_BY_NAME
	//
#pragma region "开始对新增导入表的内存进行操作"
	DWORD dwOldImportSize = sizeof(IMAGE_IMPORT_DESCRIPTOR) * dwImportDllsCount;
	CopyAndSetImportDesData(pNewPE, (PUCHAR)pImports, dwOldImportSize, FvaOff, RvaOff,pDllName,pFunctioName);

#pragma endregion

	//将原有的额外数据拷贝至新的文件中
	memcpy(pNewPE + dwNewSize, (PCHAR)pExtraDataFVA, dwExtraDataSize);
	free(pRawData);

	return pNewPE;
}

VOID MemToFile(PCHAR filePath, PCHAR pData, DWORD dwFileSize)
{
	HANDLE hFile;
 	DWORD dwBytesWritten = 0;
	BOOL bErrorFlag = FALSE;

	hFile = CreateFileA(filePath,                // name of the write
		GENERIC_WRITE,          // open for writing
		0,                      // do not share
		NULL,                   // default security
		CREATE_NEW,             // create new file only
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Terminal failure: Unable to open file \"%s\" for write.\n", filePath);
		return;
	}

	printf("Writing %d bytes to %s.\n", dwFileSize, filePath);

	bErrorFlag = WriteFile(
		hFile,           // open file handle
		pData,      // start of data to write
		dwFileSize,  // number of bytes to write
		&dwBytesWritten, // number of bytes that were written
		NULL);            // no overlapped structure

	if (FALSE == bErrorFlag)
	{

		printf("Terminal failure: Unable to write to file.\n");
	}
	else
	{
		if (dwBytesWritten != dwFileSize)
		{
			// This is an error because a synchronous write that results in
			// success (WriteFile returns TRUE) should write all data as
			// requested. This would not necessarily be the case for
			// asynchronous writes.
			printf("Error: dwBytesWritten != dwBytesToWrite\n");
		}
		else
		{
			printf("Wrote %d bytes to %s successfully.\n", dwBytesWritten, filePath);
		}
	}

	CloseHandle(hFile);
}

//
// ImportAdder.exe targetPE_path, dllname,exportFunctionName
//

int main(int argc,char* argv[])
{
	do
	{
		if (argc != 4)
		{
			printf("invalid parameters!\n you should input a fullpath file name as the second parameter!\n");
			break;
		}
		if (INVALID_FILE_ATTRIBUTES == ::GetFileAttributesA(argv[1]))
		{
			printf("invalid parameters!\n %s does not exist,please check it.\n",argv[1]);
			break;
		}
		std::string pNewFile = argv[1];
		int nPos = pNewFile.rfind(".exe");
		if (nPos != std::string::npos)
		{
			pNewFile.replace(nPos, strlen("_m.exe"), "_m.exe");
			::DeleteFileA(pNewFile.c_str());
		}

		//读取文件二进制数据
		DWORD dwFileSize = 0;
		PCHAR pFileBuffer = (PCHAR)FileToMem(argv[1], &dwFileSize);
		if (!pFileBuffer)
		{
			return 1;
		}
		printf("old file size=%d\n", dwFileSize);
		//新增节
		pFileBuffer = (PCHAR)AddNewSection(pFileBuffer, 0x200, &dwFileSize,argv[2],argv[3]);

		//将二进制数据输出到文件
		MemToFile(const_cast<CHAR *>(pNewFile.c_str()), pFileBuffer, dwFileSize);
		
	} while (false);
	
  


	getchar();
	return 0;
}
 
 