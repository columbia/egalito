#ifndef EGALITO_UTIL_FEATURE_H
#define EGALITO_UTIL_FEATURE_H

static inline bool isFeatureEnabled(const char *name) {
    const char *variable = getenv(name);

    return variable && strtol(variable, nullptr, 0) != 0;
}

#endif
