#ifndef EGALITO_GENERATE_DEFERRED_H
#define EGALITO_GENERATE_DEFERRED_H

#include <functional>
#include <string>
#include "types.h"

/** Any kind of value whose full contents are computed just-in-time.
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
    DeferredValueImpl(ElfType *elfValue) : elfValue(elfValue) {}
    virtual ~DeferredValueImpl() { delete elfValue; }

    void add(FunctionType func) { functionList.push_back(func); }
    virtual const char *getPtr() const
        { return reinterpret_cast<const char *>(elfValue); }
    virtual size_t getSize() const { return sizeof(ElfType); }
    virtual void writeTo(std::ostream &stream);
};

template <typename ElfType>
void DeferredValueImpl<ElfType>::writeTo(std::ostream &stream) {
    for(auto func : functionList) {
        func(elfValue);
    }
    DeferredValue::writeTo(stream);
}

/** Base class for list of deferred values. */
template <typename ValueType>
class DeferredListBase : public DeferredValue {
public:
    typedef ValueType ValueType;
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

template <typename ValueType>
void DeferredListBase<ValueType>::writeTo(std::ostream &stream) {
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
        { add(value); valueMap[key] = value; reverseMap[value] = key; }
    void insertAt(typename BaseType::IteratorType it, KeyType key, ValueType value)
        { insertAt(it, value); valueMap[key] = value; reverseMap[value] = key; }
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
    size_t indexOf(ValueType value) const { return indexMap[value]; }
};

template <typename ValueType>
class DeferredList : public DeferredListIndexDecorator<
    DeferredListBase<DeferredValueImpl<ValueType>>> {};

// vector, index, and map
template <typename KeyType, typename ValueType>
class DeferredMap : public DeferredListMapDecorator<
    DeferredList<ValueType>, KeyType> {};

#endif
