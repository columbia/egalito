#ifndef EGALITO_DISASM_FORMATTER_H
#define EGALITO_DISASM_FORMATTER_H

#include <string>
#include <sstream>
#include <cassert>

using namespace std;

size_t findHash(const string &str);

template <typename T> inline string toHexString(T t) {
    static_assert(std::is_integral<T>::value, "Integral required.");
    stringstream sstream;
    sstream << hex << t;
    return "0x" + sstream.str();
}

template <typename T> string replaceOne(const string &str, T t) {
    size_t pos = findHash(str);
    if (pos == string::npos) {
        assert(!"expecting #d or #x, found end of string.");
        abort();
    }

    string ret = str;
    if (str[pos + 1] == 'x') {
        ret.replace(pos, 2, toHexString(t));
    } else {
        ret.replace(pos, 2, to_string(t));
    }

    return ret;
}

template <typename T> inline string stringFormat(const string &str, T t) {
    return replaceOne(str, t);
}

template <typename T, typename... Args>
inline string stringFormat(const string &str, T t, Args... args) {
    return stringFormat(replaceOne(str, t), args...);
}

#endif
