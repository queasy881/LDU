#include <cstdio>
#include <string>
#include <vector>
#include <iostream>
int main(){
    printf("hi %d\n", 42);
    std::string s = "hello";
    std::vector<int> v; v.push_back(7); v.push_back(9);
    for (int x : v) std::cout << s << " " << x << std::endl;
    return (int)v.size();
}
