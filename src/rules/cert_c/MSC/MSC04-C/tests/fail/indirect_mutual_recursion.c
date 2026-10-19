// MSC04-C fail: two functions that call each other form an indirect
// recursion cycle; each is reported, with the cycle, at its definition.
void ping(int n);

void pong(int n) {  // expected-warning {{MSC04-C}}
    ping(n - 1);
}

void ping(int n) {  // expected-warning {{MSC04-C}}
    pong(n - 1);
}
