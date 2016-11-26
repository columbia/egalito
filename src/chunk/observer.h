#ifndef EGALITO_CHUNK_OBSERVER_H
#define EGALITO_CHUNK_OBSERVER_H

#include <vector>
#include <map>
#include <functional>
#include "event.h"

class EventObserver {
public:
    virtual ~EventObserver() {}
    virtual void handle(Event *e) = 0;
    virtual Event::EventType getType() const = 0;
};

template <typename EventType>
class TypedEventObserver : public EventObserver {
};

template <typename EventType>
class ClassEventObserver : public TypedEventObserver<EventType> {
public:
    virtual void handle(Event *e)
        { handle(static_cast<EventType *>(e)); }

    virtual void handle(EventType *e) = 0;
};

template <typename EventType>
class FunctionEventObserver : public TypedEventObserver<EventType> {
public:
    typedef std::function<void (EventType *)> FunctionType;
private:
    FunctionType func;
public:
    FunctionEventObserver(FunctionType func)
        : func(func) {}

    virtual void handle(Event *e)
        { func(static_cast<EventType *>(e)); }
};

/** Stores a list of observers for each type for easy triggering. */
class EventObserverRegistry {
private:
    typedef std::vector<EventObserver *> ObserverList;
    typedef std::map<Event::EventType, ObserverList> ObserverMatrix;
    //typedef ObserverList ObserverMatrix[Event::EVENTS];
    ObserverMatrix registry;
public:
    template <typename EventType>
    void add(TypedEventObserver<EventType> observer)
        { add(observer, EventType::type); }
    void add(EventObserver *observer, Event::EventType type);

    template <typename EventType>
    void remove(TypedEventObserver<EventType> observer)
        { remove(observer, EventType::type); }
    void remove(EventObserver *observer, Event::EventType type);

    void fire(Event *event);
};

#endif
