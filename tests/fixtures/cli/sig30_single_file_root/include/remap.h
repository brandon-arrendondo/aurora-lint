/* The project's own remapping of alarm(), in the project tree but not beside the source. */
void project_alarm(unsigned seconds);
#define alarm project_alarm
