/*
 * Rule: CON03-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON03-C violation
 */

final class ControlledStop implements Runnable {
  private boolean done = false;
 
  @Override public void run() {
    while (!isDone()) {
      try {
        // ...
        Thread.currentThread().sleep(1000); // Do something
      } catch(InterruptedException ie) { 
        Thread.currentThread().interrupt(); // Reset interrupted status
      } 
    } 	 
  }

  public synchronized boolean isDone() {
    return done;
  }

  public synchronized void shutdown() {
    done = true;
  }
}