#ifndef EGALITO_UTIL_ITER_H
#define EGALITO_UTIL_ITER_H

template <typename ValueType>
class AbstractIterator {
public:
    virtual ~AbstractIterator() {}
    virtual ValueType get() = 0;
    virtual void increment() = 0;
    virtual bool equals(const AbstractIterator<ValueType> &_other) = 0;
};

template <typename IteratorType, typename ValueType>
class STLIterator : public AbstractIterator<ValueType> {
private:
    IteratorType it;
public:
    STLIterator(IteratorType it) : it(it) {}

    virtual ValueType get() { return *it; }
    virtual void increment() { it ++; }
    virtual bool equals(const AbstractIterator<ValueType> &_other);
};

template <typename IteratorType, typename ValueType>
bool STLIterator<IteratorType, ValueType>::equals(const AbstractIterator<ValueType> &_other) {
    auto other = dynamic_cast<const STLIterator<IteratorType, ValueType> *>(&_other);
    return other && it == other->it;
}

template <typename ValueType>
class PolyIterator {
public:
    typedef AbstractIterator<ValueType> PImpl;
private:
    PImpl *it;
public:
    PolyIterator(PImpl *it) : it(it) {}
    ~PolyIterator() { delete it; }

    ValueType operator * () { return it->get(); }
    PolyIterator &operator ++ () { it->increment(); return *this; }
    bool operator == (const PolyIterator<ValueType> &other) { return it->equals(*other.it); }
    bool operator != (const PolyIterator<ValueType> &other) { return !it->equals(*other.it); }
};

template <typename ValueType, typename IteratorType = PolyIterator<ValueType>>
class IteratorGenerator {
public:
    virtual ~IteratorGenerator() {}
    virtual IteratorType begin() = 0;
    virtual IteratorType end() = 0;
};

template <typename ContainerType, typename ValueType = typename ContainerType::value_type>
class ConcreteIteratorGenerator : public IteratorGenerator<ValueType, typename ContainerType::iterator> {
public:
    typedef typename ContainerType::iterator IteratorType;
private:
    ContainerType &container;
public:
    ConcreteIteratorGenerator(ContainerType &container) : container(container) {}

    IteratorType begin() { return container.begin(); }
    IteratorType end() { return container.end(); }
};

template <typename ContainerType, typename ValueType = typename ContainerType::value_type>
class STLIteratorGenerator : public IteratorGenerator<ValueType> {
public:
    typedef PolyIterator<ValueType> IteratorType;
private:
    typedef STLIterator<typename ContainerType::iterator, ValueType> InternalIteratorType;
    ContainerType &container;
public:
    STLIteratorGenerator(ContainerType &container) : container(container) {}

    virtual IteratorType begin() { return new InternalIteratorType(container.begin()); }
    virtual IteratorType end() { return new InternalIteratorType(container.end()); }
};

template <typename ValueType, typename IteratorType = PolyIterator<ValueType>>
class Iterable {
private:
    IteratorGenerator<ValueType> *generator;
public:
    Iterable(IteratorGenerator<ValueType> *generator) : generator(generator) {}
    ~Iterable() { delete generator; }

    IteratorType begin() { return generator->begin(); }
    IteratorType end() { return generator->end(); }
};

template <typename ContainerType, typename ValueType = typename ContainerType::value_type,
    typename GeneratorType = ConcreteIteratorGenerator<ContainerType, ValueType>>
class ConcreteIterable {
public:
    typedef typename GeneratorType::IteratorType IteratorType;
private:
    GeneratorType generator;
public:
    ConcreteIterable(const GeneratorType &generator) : generator(generator) {}

    IteratorType begin() { return generator.begin(); }
    IteratorType end() { return generator.end(); }
};

#endif
