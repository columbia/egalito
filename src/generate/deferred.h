#ifndef EGALITO_GENERATE_DEFERRED_H
#define EGALITO_GENERATE_DEFERRED_H

#include <functional>
#include <string>
#include "types.h"

/** Base class for any output value which may need further computation.
*/
class DeferredValue {
public:
    virtual ~DeferredValue() {}
    virtual size_t getSize() const = 0;
    virtual void writeTo(std::ostream &stream);
};

std::ostream &operator << (std::ostream &stream, DeferredValue &dv);

class DeferredValueCString : public DeferredValue {
public:
    virtual const char *getPtr() const = 0;
    virtual void writeTo(std::ostream &stream);
};

class RawDeferredValue : public DeferredValueCString {
private:
    std::string data;
public:
    RawDeferredValue(const std::string &data) : data(data) {}

    virtual const char *getPtr() const { return data.c_str(); }
    virtual size_t getSize() const { return data.size(); }
};

template <typename ElfType>
class DeferredValueImpl : public DeferredValueCString {
public:
    typedef std::function<void (ElfType *)> FunctionType;
private:
    typedef std::vector<FunctionType> FunctionList;
    FunctionList functionList;
    ElfType *elfValue;
public:
    DeferredValueImpl(ElfType *elfValue = nullptr) : elfValue(elfValue) {}
    virtual ~DeferredValueImpl() { delete elfValue; }

    void addFunction(FunctionType func) { functionList.push_back(func); }
    ElfType *getElfPtr() const { return elfValue; }
    virtual const char *getPtr() const
        { return reinterpret_cast<const char *>(elfValue); }
    virtual size_t getSize() const { return sizeof(ElfType); }
    virtual void writeTo(std::ostream &stream);

    // basic operators to allow this type to be a key in a std::map
    bool operator < (const DeferredValueImpl<ElfType> &other) const
        { return this < &other; }
    bool operator == (const DeferredValueImpl<ElfType> &other) const
        { return this == &other; }
};

template <typename ElfType>
void DeferredValueImpl<ElfType>::writeTo(std::ostream &stream) {
    for(auto func : functionList) {
        func(elfValue);
    }
    DeferredValue::writeTo(stream);
}

/** Base class for list of deferred values. */
template <typename VType>
class DeferredListBase : public DeferredValue {
public:
    typedef VType ValueType;
    typedef std::vector<ValueType> ValueListType;
    typedef typename ValueListType::iterator IteratorType;
private:
    ValueListType valueList;
public:
    virtual ~DeferredListBase() {}
    virtual void add(ValueType value) { valueList.push_back(value); }
    virtual void insertAt(IteratorType it, ValueType value)
        { valueList.insert(it, value); }

    IteratorType begin() { return valueList.begin(); }
    IteratorType end() { return valueList.end(); }

    size_t getCount() const { return valueList.size(); }

    virtual size_t getSize() const { return getCount(); }
    virtual void writeTo(std::ostream &stream);
};

template <typename VType>
void DeferredListBase<VType>::writeTo(std::ostream &stream) {
    for(auto value : valueList) {
        value->writeTo(stream);
    }
}

template <typename BaseType, typename KeyType>
class DeferredListMapDecorator : public BaseType {
public:
    typedef typename BaseType::ValueType ValueType;
private:
    typedef std::map<KeyType, ValueType> ValueMapType;
    typedef std::map<ValueType, KeyType> ReverseMapType;
    ValueMapType valueMap;
    ReverseMapType reverseMap;
public:
    void add(KeyType key, ValueType value)
        { BaseType::add(value); valueMap[key] = value; reverseMap[value] = key; }
    void insertAt(typename BaseType::IteratorType it, KeyType key, ValueType value)
        { BaseType::insertAt(it, value); valueMap[key] = value; reverseMap[value] = key; }
    ValueType find(KeyType key) { return valueMap[key]; }
    KeyType getKey(ValueType value) { return reverseMap[value]; }
};

template <typename BaseType>
class DeferredListIndexDecorator : public BaseType {
public:
    typedef typename BaseType::ValueType ValueType;
private:
    typedef std::map<ValueType, size_t> IndexMapType;
    IndexMapType indexMap;
public:
    virtual void add(ValueType value)
        { indexMap[value] = BaseType::getCount(); BaseType::add(value); }
    virtual void insertAt(typename BaseType::IteratorType it, ValueType value)
        { indexMap[value] = it - BaseType::begin(); BaseType::insertAt(it, value); }
    size_t indexOf(ValueType value) const;
};

template <typename BaseType>
size_t DeferredListIndexDecorator<BaseType>::indexOf(ValueType value) const {
    auto it = indexMap.find(value);
    return (it != indexMap.end() ? (*it) : static_cast<size_t>(-1));
}

template <typename ValueType>
class DeferredList : public DeferredListIndexDecorator<
    DeferredListBase<DeferredValueImpl<ValueType>>> {};

// vector, index, and map
template <typename KeyType, typename ValueType>
class DeferredMap : public DeferredListMapDecorator<
    DeferredList<ValueType>, KeyType> {};

class DeferredStringList : public DeferredValue {
private:
    std::string output;
public:
    size_t add(const std::string &data, bool withNull = false);
    size_t add(const char *str, bool withNull = false);
    virtual size_t getSize() const { return output.length(); }
    virtual void writeTo(std::ostream &stream);
};

#if 0
template <typename VType>
class RawListBase : public DeferredValue {
public:
    typedef VType ValueType;
    typedef typename std::string::iterator IteratorType;
private:
    std::string output;
public:
    virtual ~DeferredListBase() {}
    virtual void add(ValueType value)
        { output.append(reinterpret_cast<const char *>(value), sizeof(value)); }
    virtual void insertAt(IteratorType it, ValueType value)
        { valueList.insert(it, value); }

    IteratorType begin() { return valueList.begin(); }
    IteratorType end() { return valueList.end(); }

    size_t getCount() const { return valueList.size(); }

    virtual size_t getSize() const { return getCount(); }
    virtual void writeTo(std::ostream &stream);
};
#endif

template <typename ValueType>
class RawDeferredList : public DeferredListIndexDecorator<
    DeferredList<ValueType>> {};

#endif
