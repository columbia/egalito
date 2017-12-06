#include "library.h"

void LibraryDependencyList::saveRole(Library *library) {
    if(library->getRole() == Library::ROLE_NORMAL
        || library->getRole() == Library::ROLE_SUPPORT) {
        
        return;
    }

    roleMap[library->getRole()] = library;
}

Library *LibraryDependencyList::byRole(Library::Role role) {
    return roleMap[role];
}
