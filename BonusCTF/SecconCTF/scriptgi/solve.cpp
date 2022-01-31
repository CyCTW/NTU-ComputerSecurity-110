#include<bits/stdc++.h>
#include<fstream>
using namespace std;

int main() {

    ifstream MyReadFile("flag.txt");
    string s;
    getline(MyReadFile, s);
    int lens = 8; // length of "<script>"
    string stk;

    for(int i=0; i < s.size(); i++) {
        int n = stk.size();
        if (n >= lens) {
            string sub;
            
            for(int k = n-lens; k < n; k++) {
              sub += stk[k];
            }

            string sub1;
            for(int j = 0; j < lens; j++) {
              sub1 += tolower(sub[j]);
            }

            if (sub1 == "<script>") {
                for(int k = 0; k < 8; k++) {
                  stk.pop_back();
                }
            }
        }
        stk.push_back(s[i]);
    }
    cout << stk << '\n';
}