/*
 * Rule: MSC13-C
 * Status: PASS - `static` locals are read at the top of the NEXT call
 * (classic ring-buffer averaging / lazy-init-guard idioms), so a write with
 * no read later in THIS call is not a dead store.
 */

#define FPS_CAPTURE_FRAMES_COUNT 30

void UpdateFPS(int fpsFrame)
{
    static float last = 0;
    static int index = 0;
    static float history[FPS_CAPTURE_FRAMES_COUNT] = { 0 };

    if ((fpsFrame - last) > 1.0f)
    {
        last = (float)fpsFrame;
        index = (index + 1) % FPS_CAPTURE_FRAMES_COUNT;
        history[index] = fpsFrame;
    }
}

void InitOnce(void)
{
    static int initialized = 0;

    if (!initialized)
    {
        initialized = 1;
    }
}
