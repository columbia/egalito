#include "state.h"

void ShellState::setChunk(Chunk *chunk) {
    if(this->chunk) reflog.push_back(this->chunk);

    this->chunk = chunk;
}

Chunk *ShellState::popReflog() {
    if(reflog.empty()) return nullptr;

    auto last = reflog.back();
    reflog.pop_back();
    return last;
}
