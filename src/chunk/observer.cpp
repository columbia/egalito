#include <algorithm>
#include "observer.h"

void EventObserverRegistry::add(EventObserver *observer,
    Event::EventType type) {

    registry[type].push_back(observer);
}

void EventObserverRegistry::remove(EventObserver *observer,
    Event::EventType type) {

    auto &v = registry[type];
    v.erase(std::remove(v.begin(), v.end(), observer), v.end());
}

void EventObserverRegistry::fire(Event *event) {
    for(auto obs : registry[event->getType()]) {
        obs->handle(event);
    }
}
