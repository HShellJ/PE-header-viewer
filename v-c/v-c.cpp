// v-c.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include <wtypes.h>
#include <winnt.h>
using namespace std;
int main(int argc,char* argv[])
{
    cout << "参考至 赵树升《计算机病毒分析与防治简明教程》" << endl;
    char* in_path = new char[4096];
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS nt_header;
    IMAGE_SECTION_HEADER* p_header;
    cout << "type your file path:";
    cin >> in_path;
    
    FILE *file = fopen(in_path, "r+");
    if (file == NULL) {
        cout << "wrong with opening file " << in_path << "\nexit." << endl;
        return 1;
    }
    fread(&dos_header,sizeof(dos_header),1,file);
    if (dos_header.e_magic != 0x5a4d) {
        cout << "no dos header" << endl;
        return 1;
    }
    fseek(file, dos_header.e_lfanew, SEEK_SET);
    
    fread(&nt_header, sizeof(nt_header), 1, file);
    if (nt_header.Signature != 0x00004550) {
        cout << "no PE header" << endl;
        return 1;
    }
    p_header = new IMAGE_SECTION_HEADER[nt_header.FileHeader.NumberOfSections];
    fread(p_header, sizeof(IMAGE_SECTION_HEADER)*nt_header.FileHeader.NumberOfSections, 1, file);

    cout << "VA=" << nt_header.OptionalHeader.ImageBase << "\nRVA=" << nt_header.OptionalHeader.AddressOfEntryPoint << "\n节数=" << nt_header.FileHeader.NumberOfSections << endl;
    cout << "节的文件对齐粒度=" << nt_header.OptionalHeader.FileAlignment << "\n节的内存对齐粒度" << nt_header.OptionalHeader.SectionAlignment << endl;
    for (register int i = 0; i < nt_header.FileHeader.NumberOfSections; i++) {
        cout << ".....第" << i << "节....." << endl;
        cout << "Name=" << p_header[i].Name << "\n节RVA=" << p_header[i].VirtualAddress << "\n节文件偏移=" << p_header[i].PointerToRawData << "\n节实际大小=" << p_header[i].Misc.VirtualSize << "\n对齐后大小=" << p_header[i].SizeOfRawData << endl;
    }
    cout << "done" << endl;
    fclose(file);
    delete[] in_path;
    return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
