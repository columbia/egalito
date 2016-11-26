#ifndef EGALITO_CHUNK_EVENT_H
#define EGALITO_CHUNK_EVENT_H

class Chunk;  // forward declaration
class Link;

/** Represents a notification in or modification of the Chunk tree. */
class Event {
public:
    enum EventType {
        EVENT_RESIZE,
        EVENT_MOVE_SOURCE,
        EVENT_MOVE_TARGET,
        EVENT_ADD_LINK,
        EVENT_RE_ENCODE,
        EVENTS
    };
private:
    Chunk *origin;
public:
    Event(Chunk *origin) : origin(origin) {}
    virtual ~Event() {}

    virtual EventType getType() const = 0;
    Chunk *getOrigin() const { return origin; }
};

template <Event::EventType Type>
class EventBase : public Event {
public:
    static const EventType type = Type;
    virtual EventType getType() const { return type; }
};

class ResizeEvent : public EventBase<Event::EVENT_RESIZE> {
public:
};
class MoveSourceEvent : public EventBase<Event::EVENT_MOVE_SOURCE> {
public:
};
class MoveTargetEvent : public EventBase<Event::EVENT_MOVE_TARGET> {
public:
};
class AddLinkEvent : public EventBase<Event::EVENT_ADD_LINK> {
private:
    Link *link;
public:
    Link *getLink() const { return link; }
};
class ReEncodeEvent : public EventBase<Event::EVENT_RE_ENCODE> {
public:
};

#endif
