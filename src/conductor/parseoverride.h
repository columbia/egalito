#ifndef EGALITO_CONDUCTOR_PARSE_OVERRIDE_H
#define EGALITO_CONDUCTOR_PARSE_OVERRIDE_H

#include <experimental/optional>
#include <vector>
#include <map>
#include <string>
#include <type_traits>

#include "types.h"

class BlockBoundaryOverride {
public:
    typedef std::vector<std::pair<address_t, size_t>> OverrideList;
private:
    OverrideList overrideList;
public:
    const OverrideList &getOverrideList() const { return overrideList; }

    static BlockBoundaryOverride *parse(std::istream &stream,
        std::string &line);
};

typedef std::tuple<
    // module name
    std::experimental::optional<std::string>,
    // function name
    std::experimental::optional<std::string>,
    // address or offset
    std::experimental::optional<address_t>> OverrideContext;

template <class First, class ...Args>
std::tuple<Args...> drop_first(std::tuple<First, Args...>);

template<typename T, typename TT>
class OverrideContainer;

template<typename T>
class OverrideContainer<T, std::tuple<>> {
public:
    typedef T *type;
};

template<typename T, typename TT>
class OverrideContainer {
public:
    typedef std::map<
        typename std::remove_reference<decltype(std::get<0>(TT{}))>::type,
        typename OverrideContainer<T, decltype(drop_first(TT{}))>::type>
        type;
};

template<typename ContainerType, typename Accumulator>
class OverrideContainerLookup;

template<typename ContainerType, typename TC>
class OverrideContainerLookup<ContainerType, std::tuple<TC>> {
public:
    template<typename MT, typename TT>
    static ContainerType *lookup(const MT &container, const TT &context) {
        auto it = container.find(std::get<
            std::tuple_size<TT>::value - 1>(context));
        if(it == container.end()) return nullptr;
        return it->second;
    }
};

template<typename ContainerType, typename Accumulator>
class OverrideContainerLookup {
public:
    template<typename MT, typename TT>
    static ContainerType *lookup(const MT &container, const TT &context) {
        using NextLookup = OverrideContainerLookup<ContainerType,
            decltype(drop_first(Accumulator{}))>;

        auto it = container.find(std::get<
                std::tuple_size<TT>::value - std::tuple_size<Accumulator
            >::value>(context));
        ContainerType *result = nullptr;
        if(it != container.end())
            result = NextLookup::lookup(it->second, context);
        if(result) return result;

        it = container.find(std::experimental::nullopt);
        if(it != container.end())
            result = NextLookup::lookup(it->second, context);
        return result;
    }
};

template<typename ContainerType, typename Accumulator>
class OverrideContainerInsert;

template<typename ContainerType, typename TC>
class OverrideContainerInsert<ContainerType, std::tuple<TC>> {
public:
    template<typename MT, typename TT>
    static void insert(MT &container, const TT &context, ContainerType *value) {
        container[std::get<
            std::tuple_size<TT>::value - 1>(context)] = value;
    }
};

template<typename ContainerType, typename Accumulator>
class OverrideContainerInsert {
public:
    template<typename MT, typename TT>
    static void insert(MT &container, const TT &context, ContainerType *value) {
        using NextInsert = OverrideContainerInsert<ContainerType,
            decltype(drop_first(Accumulator{}))>;

        NextInsert::insert(container[std::get<
                std::tuple_size<TT>::value - std::tuple_size<Accumulator
            >::value>(context)], context, value);
    }
};

class ParseOverride {
private:
    static ParseOverride instance;
    ParseOverride() {}
public:
    static ParseOverride *getInstance() { return &instance; }
private:
    std::string currentModule;

    OverrideContainer<
        BlockBoundaryOverride, OverrideContext>::type blockOverrides;
public:
    const std::string &getCurrentModule() const { return currentModule; }
    void setCurrentModule(const std::string &name) { currentModule = name; }
    void clearCurrentModule() { currentModule = ""; }

    OverrideContext makeContext(const std::string &functionName) {
        return OverrideContext(
            currentModule, functionName, std::experimental::nullopt);
    }

    OverrideContext makeContext(address_t address) {
        return OverrideContext(
            currentModule, std::experimental::nullopt, address);
    }

    // override lookups
    BlockBoundaryOverride *getBlockBoundaryOverride(
        const OverrideContext &where);

    void parse(const std::string &from);
private:
    void parseFile(const std::string &filename);
    void parseBlockOverride(std::istream &stream);
};

#endif
