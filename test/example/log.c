
static void entryAdvice(void) __attribute__((used));
static void exitAdvice(void) __attribute__((used));

static int entry_count, exit_count;

void entryAdvice(void) { entry_count++; }
void exitAdvice(void) { exit_count++; }

int main(void)
{

    return 0;
}
