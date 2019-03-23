#include "state.h"

void ShellState::setChunk(Chunk *chunk) {
    if(this->chunk) reflog.push_back(this->chunk);

    this->chunk = chunk;
}
