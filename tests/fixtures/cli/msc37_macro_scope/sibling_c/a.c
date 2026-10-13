
void stop(void);

int g(int k)
{
    switch (k) {
    case 1:
        return 1;
    default:
        stop();
        break;
    }
}
