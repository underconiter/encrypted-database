#include <iostream>
#include <stdio.h>
#include <fstream>
#include <cstdlib>
#include <Windows.h>
#include <string>
#include <cstring>
#include<vector>
#include<cryptopp/aes.h>
#include<string>
#include "md5.h"
#include <aes.h>  
#include <cryptopp/Hex.h>      // StreamTransformationFilter  
#include <cryptopp/modes.h> // CFB_Mode  
#include<winsock.h>
#include<mysql.h>
#include "sha.h"
#include "filters.h"
#include "base64.h"



using namespace CryptoPP;
#pragma comment( lib, "cryptlib.lib" )
using namespace std;

extern bool inputcheck(string);

MYSQL m;//mysql链接
MYSQL_RES* res; //查询结果
MYSQL_ROW row;//二维数组

static string s_sha256;
static string aesKey;
static string aesIV = "ABCDEF0123456789ABCDEF0123456789";//256 bits  




string SHA256HashString(std::string aString) {
	string digest;
	CryptoPP::SHA256 hash;

	CryptoPP::StringSource foo(aString, true,
		new CryptoPP::HashFilter(hash,
			new CryptoPP::HexEncoder(
				new CryptoPP::StringSink(digest))));

	return digest;
}



std::string CFB_AESEncryptStr(std::string sKey, std::string sIV, const char* plainText)//加密程序
{
	std::string outstr;

	//填key    
	SecByteBlock key(AES::MAX_KEYLENGTH);
	memset(key, 0x30, key.size());
	sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

	//填iv    
	byte iv[AES::BLOCKSIZE];
	memset(iv, 0x30, AES::BLOCKSIZE);
	sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);

	AES::Encryption aesEncryption((byte*)key, AES::MAX_KEYLENGTH);

	CFB_Mode_ExternalCipher::Encryption cfbEncryption(aesEncryption, iv);

	StreamTransformationFilter cfbEncryptor(cfbEncryption, new HexEncoder(new StringSink(outstr)));
	cfbEncryptor.Put((byte*)plainText, strlen(plainText));
	cfbEncryptor.MessageEnd();

	return outstr;
}


std::string CFB_AESDecryptStr(std::string sKey, std::string sIV, const char* cipherText)//解密程序
{
	std::string outstr;

	//填key    
	SecByteBlock key(AES::MAX_KEYLENGTH);
	memset(key, 0x30, key.size());
	sKey.size() <= AES::MAX_KEYLENGTH ? memcpy(key, sKey.c_str(), sKey.size()) : memcpy(key, sKey.c_str(), AES::MAX_KEYLENGTH);

	//填iv    
	byte iv[AES::BLOCKSIZE];
	memset(iv, 0x30, AES::BLOCKSIZE);
	sIV.size() <= AES::BLOCKSIZE ? memcpy(iv, sIV.c_str(), sIV.size()) : memcpy(iv, sIV.c_str(), AES::BLOCKSIZE);

	CFB_Mode<AES >::Decryption cfbDecryption((byte*)key, AES::MAX_KEYLENGTH, iv);

	HexDecoder decryptor(new StreamTransformationFilter(cfbDecryption, new StringSink(outstr)));
	decryptor.Put((byte*)cipherText, strlen(cipherText));
	decryptor.MessageEnd();

	return outstr;
}


void mysqlconnect() {


	//初始化数据库
	mysql_init(&m);

	//设置编码方式
	mysql_options(&m, MYSQL_SET_CHARSET_NAME, "gbk");

	//连接数据库

	if (mysql_real_connect(&m, "localhost", "root", "6621416", "mydb", 3306, NULL, 0)) {
		//主机，用户名，密码，数据库名称，端口
		cout << "数据库连接成功" << endl;

	}
	else {
		cout << "数据库连接失败" << mysql_error(&m) << endl;
	}
}




void display()
{

	//查询数据
	int ret = mysql_query(&m, "select * from connecttable;");

	//获取结果集
	res = mysql_store_result(&m);

	cout<<"    " << "Name " << "  " << "Position " << "       " << "Tel" << "      " << "Email" << endl;
	//给ROW赋值，判断ROW是否为空，不为空就打印数据。
	while (row = mysql_fetch_row(res))
	{
		string name = row[0];
		string position = row[1];
		string tel = row[2];
		string email = row[3];

		cout << "    " << CFB_AESDecryptStr(aesKey, aesIV, name.c_str());
		cout << "    " << CFB_AESDecryptStr(aesKey, aesIV, position.c_str());
		cout << "    " << CFB_AESDecryptStr(aesKey, aesIV, tel.c_str());
		cout << "    " << CFB_AESDecryptStr(aesKey, aesIV, email.c_str()) << endl;
	}
	//释放结果集
	mysql_free_result(res);

}


void insert(MYSQL* conn,  char name[48], char position[48],  char tel[48],  char email[48])
//void insert()
//插入数据
{

	string s;
	char str[64] = "INSERT INTO connecttable VALUES('";
	char buffer[512] = { 0 };
	char str2[4] = "','";
	char str3[4] = "','";
	char str4[4] = "','";
	char str5[4] = "');";
	int len = sprintf_s(buffer, "%s%s%s%s%s%s%s%s%s", str, name, str2, position, str3, tel, str4, email, str5);
	mysql_query(&m, buffer);
	if (len < 0)
		cout << "存档失败！" << endl;
	if (len > 0)
		cout << "存档成功！" << endl;
	mysql_free_result(res);

}

//查询特定数据
void selectdb( char str[])
{
	
	char str1[64] = "SELECT * FROM connecttable WHERE NAME='";
	char str2[5] = "';";
	char buffer[1024];//缓冲区数组
	string name;
	string position;
	string tel;
	string email;

	sprintf_s(buffer, "%s%s%s", str1, str, str2);
	mysql_query(&m, buffer);
	res = mysql_store_result(&m);
	
	
	//给ROW赋值，判断ROW是否为空，不为空就打印数据。
	while (row = mysql_fetch_row(res))
	{
		 name = row[0];
		position = row[1];
		 tel = row[2];
		 email = row[3];
		cout << "Name=" << CFB_AESDecryptStr(aesKey, aesIV, name.c_str()) << endl;
		cout << " Position=" << CFB_AESDecryptStr(aesKey, aesIV, position.c_str()) << endl;
		cout << "Tel=" << CFB_AESDecryptStr(aesKey, aesIV, tel.c_str()) << endl;
		cout << " Email=" << CFB_AESDecryptStr(aesKey, aesIV, email.c_str()) << endl;
	}
	char* name_n = (char*)name.c_str();
	if (0 == strlen(name_n))
	{
		cout << "查无此人" << endl;
	}
	//释放结果集
	mysql_free_result(res);
	
}



void deletedb(char str2[])
//删除数据
{
	char str1[64] = "DELETE FROM connecttable WHERE name='";
	char str3[10] = "'";
	char buffer[1024];
	int len = sprintf_s(buffer, "%s%s%s", str1, str2, str3);
	mysql_query(&m, buffer);
	if (len < 0)
		cout << "删除失败！" << endl;
	else
		cout << "删除成功！" << endl;

}

//验证密码
int passwordcheck() {
	string password;
	string s_passwordcheck;
	cout << "请输入密码" << endl;
	cin >> password;
	s_passwordcheck = SHA256HashString(password);
	if ((s_passwordcheck.compare(s_sha256)) == 0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}





// 菜单界面
void showMenu() {
	cout << "***************************" << endl;
	cout << "*****  1、添加联系人  *****" << endl;
	cout << "*****  2、显示联系人  *****" << endl;
	cout << "*****  3、查找联系人  *****" << endl;
	cout << "*****  4、删除联系人  *****" << endl;
	cout << "*****  5、输入密码    *****" << endl;
	cout << "*****  0、退出通讯录  *****" << endl;
	cout << "***************************" << endl;

}

// 1、添加联系人信息
void addPerson() {

	
		// 姓名
		string name;
		string cipherText_m;
		string decryptedText;
		cout << "请输入姓名：" << endl;
		cin >> name;
		if (inputcheck(name))
		{
			system("pause");
			system("cls");
			return;
		}
		cipherText_m = CFB_AESEncryptStr(aesKey, aesIV, name.c_str());

	


		//职位
		string Position;
		string cipherText_p;
		cout << "请输入职位：" << endl;
		cin >> Position;
		if (inputcheck(Position))
	    {
			system("pause");
			system("cls");
			return;
		}
		cipherText_p = CFB_AESEncryptStr(aesKey, aesIV, Position.c_str());
	
		
	


		// 联系电话
		cout << "请输入联系电话：" << endl;
		string tel = "";
		string cipherText_t;
		cin >> tel;
		if (inputcheck(tel))
		{
			system("pause");
			system("cls");
			return;
	    }
		cipherText_t = CFB_AESEncryptStr(aesKey, aesIV, tel.c_str());
		


		// 邮箱
		string email;
		string cipherText_e;
		cout << "请输入邮箱：" << endl;
		cin >> email;
		if (inputcheck(email))
		{
			system("pause");
			system("cls");
			return;
		}
		cipherText_e = CFB_AESEncryptStr(aesKey, aesIV, email.c_str());

		
		char *name_m =  (char*)cipherText_m.c_str() ;
		char *position_p =  (char*)cipherText_p.c_str() ;
		char *tel_t = (char*)cipherText_t.c_str();
		char *email_e =  (char*)cipherText_e.c_str() ;
		//cout <<  name_m;
		//cout << position_p;
		//cout << tel_t;
		//cout << email_e;

		insert(&m, name_m, position_p, tel_t, email_e);
		

		cout << "添加完成" << endl;
		system("pause");
		system("cls");
	
}

// 2、显示所有联系人信息
void showPerson() {
	int flag;
	flag = passwordcheck();
	if (!flag)
	{
		cout << "密码错误，非法访问" << endl;
		system("pause");
		system("cls");
		return;
	}
	else {
		display(); 
	}

	system("pause");
	system("cls");
}



// 3、查找指定联系人信息
void findPerson() {
	cout << "请输入您要查找的联系人" << endl;
	string name;
	string cipherText_m;
	cin >> name;
	if (inputcheck(name))
	{
		system("pause");
		system("cls");
		return;
	}
	cipherText_m = CFB_AESEncryptStr(aesKey, aesIV, name.c_str());
	char* name_m = (char*)cipherText_m.c_str();
	selectdb(name_m);

	system("pause");
	system("cls");
}


// 4、删除指定联系人信息
void deletesb()
{
	cout << "请输入您要删除的联系人" << endl;
	string name;
	string cipherText_m;
	cin >> name;
	cipherText_m = CFB_AESEncryptStr(aesKey, aesIV, name.c_str());
	char* name_m = (char*)cipherText_m.c_str();
	deletedb(name_m);
	system("pause");
	system("cls");
}




//设置密码
void password()
{
	string password;
	string test;
	cout << "请输入密码" << endl;
	cin >> password;
	s_sha256 = SHA256HashString(password);
	aesKey = s_sha256;//设置密钥
	system("pause");
	system("cls");

}






int main() {
	int select = 0;
	mysqlconnect();
	password();
	while (true) {
		showMenu();  // 显示菜单
		cin >> select;  // 输入选项

		switch (select) {
		case 1:  // 添加联系人
			addPerson();
			break;
		case 2:  // 显示联系人
			showPerson();
			break;
	
		case 3:  // 查找联系人
			findPerson();
			break;
		case 4:  // 删除联系人
			deletesb();
			break;
		case 5:  // 修改密码
			password();
			break;
		case 0:  // 退出通讯录
			cout << "欢迎再次使用~" << endl;
			system("pause");
			mysql_close(&m);//断开数据库
			return 0;
			break;
		default:
			break;
		}
	}

	system("pause");
	return 0;
}
