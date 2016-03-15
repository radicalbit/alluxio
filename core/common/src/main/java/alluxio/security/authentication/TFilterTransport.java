/*
 * The Alluxio Open Foundation licenses this work under the Apache License, version 2.0
 * (the “License”). You may not use this work except in compliance with the License, which is
 * available at www.apache.org/licenses/LICENSE-2.0
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied, as more fully set forth in the License.
 *
 * See the NOTICE file distributed with this work for information regarding copyright ownership.
 */

package alluxio.security.authentication;

import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportException;

/**
 * Transport that simply wraps another transport. This is the equivalent of FilterInputStream for
 * Thrift transports.
 */
public class TFilterTransport extends TTransport {
  private final TTransport mWrapped;

  public TFilterTransport(TTransport wrapped) {
    mWrapped = wrapped;
  }

  protected TTransport getWrapped() {
    return mWrapped;
  }

  @Override
  public void open() throws TTransportException {
    mWrapped.open();
  }

  @Override
  public boolean isOpen() {
    return mWrapped.isOpen();
  }

  @Override
  public boolean peek() {
    return mWrapped.peek();
  }

  @Override
  public void close() {
    mWrapped.close();
  }

  @Override
  public int read(byte[] buf, int off, int len) throws TTransportException {
    return mWrapped.read(buf, off, len);
  }

  @Override
  public int readAll(byte[] buf, int off, int len) throws TTransportException {
    return mWrapped.readAll(buf, off, len);
  }

  @Override
  public void write(byte[] buf) throws TTransportException {
    mWrapped.write(buf);
  }

  @Override
  public void write(byte[] buf, int off, int len) throws TTransportException {
    mWrapped.write(buf, off, len);
  }

  @Override
  public void flush() throws TTransportException {
    mWrapped.flush();
  }

  @Override
  public byte[] getBuffer() {
    return mWrapped.getBuffer();
  }

  @Override
  public int getBufferPosition() {
    return mWrapped.getBufferPosition();
  }

  @Override
  public int getBytesRemainingInBuffer() {
    return mWrapped.getBytesRemainingInBuffer();
  }

  @Override
  public void consumeBuffer(int len) {
    mWrapped.consumeBuffer(len);
  }
}
