/* The project's own remapping of a name on the async-signal-safe list. */
void project_alarm(unsigned seconds);
#define alarm project_alarm
