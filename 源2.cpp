#include <iostream>
#include <stdio.h>

using namespace std;
bool inputcheck(string uncheck) {
	if (uncheck.length()>=24)
	{
		cout << "输入长度大于标准长度，请重新输入" << endl;
		return true;

	}
	else
	{
		return false;
	}

}
