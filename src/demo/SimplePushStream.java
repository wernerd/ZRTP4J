package demo;

import javax.media.*;
import javax.media.format.*;
import javax.media.protocol.*;

public class SimplePushStream implements PushSourceStream, PushBufferStream {

    protected ContentDescriptor cd;

    @SuppressWarnings("unused")
    private SourceTransferHandler sth = null;

    private BufferTransferHandler bth = null;

    private AudioFormat af = null;

    private String sendData = "0123456789";

    private byte[] sendBytes = null;

    private byte[] myBuffer = null;

    public SimplePushStream() {
        cd = new ContentDescriptor("unknown");
        af = new AudioFormat(AudioFormat.ULAW_RTP, 8000.0, 8, 1);
//        System.err.println("AF: " + af.toString());
        sendBytes = sendData.getBytes();
        myBuffer = new byte[sendBytes.length];
    }

    /*
     * Interface methods of PushSourceStream
     */
    public int getMinimumTransferSize() {
        return 0;
    }

    public int read(byte[] buffer, int offset, int length)
            throws java.io.IOException {
        System.err.println("SimplePushStream::read(...)");
        return 0;
    }

    public void setTransferHandler(SourceTransferHandler transferHandler) {
        System.err.println("SimplePushStream::setTransferHandler()");
        sth = transferHandler;
    }

    /*
     * Interface methods of PushBufferStream
     */
    public void setTransferHandler(BufferTransferHandler transferHandler) {
        System.err.println("SimplePushStream::setTransferHandler()");
        bth = transferHandler;
    }

    public void read(Buffer buffer) throws java.io.IOException {
        // System.err.println("SimplePushStream::read(Buffer)");

        buffer.setFormat(af);

        // The pre-allocated buffer is usually the one we handed over the first
        // time
        if (buffer.getData() != null) {
            byte[] arr = (byte[]) buffer.getData();
            // System.err.println("preallocated buffer length: " + arr.length);
            System.arraycopy(sendBytes, 0, arr, buffer.getOffset(), sendBytes.length);
            buffer.setLength(sendBytes.length);
        } else {
            System.arraycopy(sendBytes, 0, myBuffer, 0, myBuffer.length);
            buffer.setData(myBuffer);
            buffer.setLength(myBuffer.length);
        }
        buffer.setOffset(0);
        sendBytes[0] += 1;
    }

    public Format getFormat() {
        System.err.println("SimplePushStream::getFormat()");
        return af;
    }

    /*
     * Interface methods of SourceStream
     */

    public ContentDescriptor getContentDescriptor() {
        System.err.println("SimplePushStream::getContentDescriptor()");
        return cd;
    }

    public long getContentLength() {
        System.err.println("SimplePushStream::getContentLength()");
        return SourceStream.LENGTH_UNKNOWN;
    }

    public boolean endOfStream() {
        return false;
    }

    /*
     * Interface methods of Controls
     */

    public java.lang.Object[] getControls() {
        System.err.println("SimplePushStream::getControls()");
        return null;
    }

    public java.lang.Object getControl(java.lang.String controlType) {
        System.err.println("SimplePushStream::getControl(" + controlType + ")");
        return "unknown";
    }

    public void pushData() {
        // System.err.println("SimplePushStream::pushData()");
        if (bth != null) {
            bth.transferData(this);
        }
    }
}
