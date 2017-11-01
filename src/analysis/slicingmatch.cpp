#include "slicingmatch.h"

void TreeCapture::append(const TreeCapture& capture) {
    captureList.insert(captureList.end(),
        capture.captureList.begin(), capture.captureList.end());
}
