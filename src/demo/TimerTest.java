package demo;

public class TimerTest {

    class Timeout extends Thread {

        public Timeout(String name) {
            super(name);
        }

        TimerTest executor;

        long nextDelay = 0;

        boolean newTask = false;

        boolean stop = false;

        Object sync = new Object();

        public synchronized void newTask(TimerTest tt, long delay) {
            synchronized (sync) {
                executor = tt;
                nextDelay = delay;
                newTask = true;
                sync.notifyAll();
            }
        }

        public void stopRun() {
            System.err.println("Stop run");
            synchronized (sync) {
                stop = true;
                sync.notifyAll();
            }
        }

        public void cancelRequest() {
            synchronized (sync) {
                newTask = false;
                sync.notifyAll();
            }
        }
        
        public void run() {
            synchronized (sync) {
                while (!stop) {
                    while (!newTask && !stop) {
                        System.err.println("waiting for new task");
                        try {
                            sync.wait();
                        } catch (InterruptedException e) {
                        }
                    }
                    long endTime = System.currentTimeMillis() + nextDelay;
                    long currentTime = System.currentTimeMillis();
                    while ((currentTime < endTime) && newTask && !stop) {
                        System.err.println("Got new task, wait for its timer");
                        try {
                            sync.wait(endTime - currentTime);
                        } catch (InterruptedException e) {
                        }
                        currentTime = System.currentTimeMillis();
                    }
                    if (newTask && !stop) {
                        executor.handleTimer();
                        newTask = false;
                    }
                }
            }
            System.err.println("run done");
        }
    }
    
    Timeout tmo = null;
    
    
    public TimerTest() {
        tmo = new Timeout("ZRTP");
        tmo.start();
    }
    
    void doTest2() {
        tmo.newTask(this, 2000);
        System.err.println("Current time: " + System.currentTimeMillis());
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        System.err.println("Seccond timer task schedule");
        tmo.newTask(this, 1000);
        System.err.println("Current time: " + System.currentTimeMillis());
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        System.err.println("Third timer task schedule");
        tmo.newTask(this, 3000);
        System.err.println("Current time: " + System.currentTimeMillis());
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        tmo.cancelRequest();
        try {
            Thread.sleep(4000);
        } catch (InterruptedException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        
        tmo.stopRun();    
    }
    
    void handleTimer() {
        System.err.println("in handletimer at: " + System.currentTimeMillis());
    }
    public static void main(String[] args) {
        TimerTest tt = new TimerTest();
        tt.doTest2();
    }
}
