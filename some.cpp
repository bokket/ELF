#include <stdio.h>
#include <iostream>
#include <jsoncpp/json/json.h>
using namespace std;
int main()
{
     Json::Value root;
    Json::Value arrayObj;
    Json::Value item;
    for (int i=0; i<10; i++)
    {
    item["key"] = i;
    arrayObj.append(item);
    }

    root["key1"] = "value111";
    root["key2"] = "value2111";
    root["array"] = arrayObj;
    root.toStyledString();
    std::string out = root.toStyledString();
    std::cout << out << std::endl;
}
