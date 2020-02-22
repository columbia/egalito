#include "framework/include.h"
#include "log/registry.h"
#include "log/temp.h"

TEST_CASE("set temporary log level", "[log][fast][.]") {
    GroupRegistry::getInstance()->muteAllSettings();

    SECTION("single case") {
        TemporaryLogLevel tll("chunk", 10);
        CHECK(GroupRegistry::getInstance()->getSetting("chunk") == 10);
    }

    SECTION("nested case") {
        TemporaryLogLevel tll("chunk", 10);
        {
            TemporaryLogLevel tll("chunk", 20);
            CHECK(GroupRegistry::getInstance()->getSetting("chunk") == 20);
        }
        CHECK(GroupRegistry::getInstance()->getSetting("chunk") == 10);
    }
}
