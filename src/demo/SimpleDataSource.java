package demo;

import javax.media.*;
import javax.media.protocol.*;

public class SimpleDataSource extends PushBufferDataSource {

    protected ContentDescriptor cd;

    SimplePushStream[] spsArray = new SimplePushStream[1];

    public SimpleDataSource() {
        cd = new ContentDescriptor("unknown");
        spsArray[0] = new SimplePushStream();
    }

    /*
     * Interface methods of PushDataSource
     */
    public PushBufferStream[] getStreams() {
        System.out.println("SimpleDataSource::getStreams()");
        return spsArray;
    }

    /*
     * Methods of DataSource
     */
    public void setLocator(MediaLocator source) {
    }

    public MediaLocator getLocator() {
        System.out.println("SimpleDataSource::getLocator()");
        return null;
    }

    protected void initCheck() {
    }

    public java.lang.String getContentType() {
        System.out.println("SimpleDataSource::getContetnType()");
        return "unknown";
    }

    public void connect() throws java.io.IOException {
        System.out.println("SimpleDataSource::connect()");
        /*
         * connected = true; sources = new SeekableStream [1]; sources[0] = new
         * SeekableStream(anInput);
         */

    }

    public void disconnect() {
    }

    public void start() throws java.io.IOException {
        System.out.println("SimpleDataSource::start()");
    }

    public void stop() throws java.io.IOException {
    }

    /*
     * Interface methods of Duration
     */
    public javax.media.Time getDuration() {
        System.out.println("SimpleDataSource::getDuration()");
        return Duration.DURATION_UNKNOWN;
    }

    /*
     * Interface methods of Controls
     */
    public java.lang.Object[] getControls() {
        System.out.println("SimpleDataSource::getStreams()");
        return null;
    }

    public java.lang.Object getControl(java.lang.String controlType) {
        System.out.println("SimpleDataSource::getControl(" + controlType + ")");
        return cd;
    }

    public void pushData() {
        // System.out.println("SimpleDataSource::pushData()");
        spsArray[0].pushData();
    }

}

