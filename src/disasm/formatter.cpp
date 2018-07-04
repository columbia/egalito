#include "disasm/assemblyFormatter.h"

size_t findHash(const string &str) {
    size_t startPos = 0;
    while (true) {
        size_t pos = str.find('#', startPos);
        if (pos == string::npos)
            return string::npos;
        if (pos == str.length() - 1)
            return string::npos;
        if (str[pos + 1] == '#')
            startPos = pos + 2;
        if (str[pos + 1] != 'x' && str[pos + 1] != 'd' && str[pos + 1] != 's')
            startPos = pos + 2;
        else
            return pos;
    }
}

template <>
inline string replaceOne<const char *>(const string &str, const char *t) {
    size_t pos = findHash(str);
    if (str[pos + 1] == 's') {
        string ret = str;
        ret.replace(pos, 2, t);
        return ret;
    }

    return str;
}
