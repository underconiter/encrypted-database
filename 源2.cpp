#include <iostream>
#include <stdio.h>

using namespace std;
bool inputcheck(string uncheck) {
	if (uncheck.length()>=24)
	{
		cout << "���볤�ȴ��ڱ�׼���ȣ�����������" << endl;
		return true;

	}
	else
	{
		return false;
	}

}
