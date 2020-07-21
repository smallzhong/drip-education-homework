#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <stdlib.h>

using namespace std;

struct Base
{
public:
    virtual void Function_1()
    {
        printf("Base:Function_1...\n");
    }
    virtual void Function_2()
    {
        printf("Base:Function_2...\n");
    }
    virtual void Function_3()
    {
        printf("Base:Function_3...\n");
    }
};
struct Sub : Base
{
public:
    virtual void Function_1()
    {
        printf("Sub:Function_1...\n");
    }
    virtual void Function_2()
    {
        printf("Sub:Function_2...\n");
    }
    virtual void Function_6()
    {
        printf("Sub:Function_6...\n");
    }
};

int main()
{
    Sub sub;
    printf("this指针指向的地址：%x\n", &sub);
    PDWORD pVirtualTable = (PDWORD)(*(PDWORD)&sub);
    printf("虚表的地址：%x\n", pVirtualTable);
    int ct = 1;
    while (*pVirtualTable != 0)
    {
        printf("虚表中第%d个函数的地址为0x%x\n", ct++, *(pVirtualTable++));
    }
    return 0;
}