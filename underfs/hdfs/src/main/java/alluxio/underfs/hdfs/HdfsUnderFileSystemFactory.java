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

package alluxio.underfs.hdfs;

import alluxio.Configuration;
import alluxio.underfs.UnderFileSystem;
import alluxio.underfs.UnderFileSystemFactory;

import com.google.common.base.Preconditions;
import org.apache.hadoop.fs.FileSystem;

import javax.annotation.concurrent.ThreadSafe;

/**
 * Factory for creating {@link HdfsUnderFileSystem}.
 *
 * It caches created {@link HdfsUnderFileSystem}s, using the scheme and authority pair as the key.
 */
@ThreadSafe
public final class HdfsUnderFileSystemFactory implements UnderFileSystemFactory {
  /**
   * Cache mapping {@code Path}s to existing {@link UnderFileSystem} instances. The paths should be
   * normalized to root paths because only their schemes and authorities are needed to identify
   * which {@link FileSystem} they belong to.
   */
//  private Map<Path, HdfsUnderFileSystem> mHdfsUfsCache = Maps.newHashMap();

  @Override
  public UnderFileSystem create(String path, Configuration configuration, Object conf) {
    Preconditions.checkArgument(path != null, "path may not be null");
    return new HdfsUnderFileSystem(path, configuration, conf);
  }

  @Override
  public boolean supportsPath(String path, Configuration conf) {
    if (path == null) {
      return false;
    }

    return UnderFileSystem.isHadoopUnderFS(path, conf);
  }
}
