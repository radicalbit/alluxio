/*
 * Licensed to the University of California, Berkeley under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The ASF licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License. You may obtain a
 * copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */

package tachyon.metrics;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import javax.annotation.concurrent.NotThreadSafe;

import com.codahale.metrics.Counter;
import com.codahale.metrics.Metric;
import com.google.common.base.Preconditions;
import com.google.common.collect.Iterables;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.codahale.metrics.MetricRegistry;

import tachyon.Constants;
import tachyon.conf.TachyonConf;
import tachyon.metrics.sink.CsvSink;
import tachyon.metrics.sink.MetricsServlet;
import tachyon.metrics.sink.Sink;
import tachyon.metrics.source.Source;
/**
 * A MetricsSystem is created by a specific instance(master, worker). It polls the metrics sources
 * periodically and pass the data to the sinks.
 *
 * The syntax of the metrics configuration file is:
 * [instance].[sink|source].[name].[options]=[value]
 */
@NotThreadSafe
public class MetricsSystem {
  private static final Logger LOG = LoggerFactory.getLogger(Constants.LOGGER_TYPE);

  public static final String SINK_REGEX = "^sink\\.(.+)\\.(.+)";
  public static final String SOURCE_REGEX = "^source\\.(.+)\\.(.+)";
  private static final TimeUnit MINIMAL_POLL_UNIT = TimeUnit.SECONDS;
  private static final int MINIMAL_POLL_PERIOD = 1;

  private String mInstance;
  private List<Sink> mSinks = new ArrayList<Sink>();
  private List<Source> mDefaultSources = new ArrayList<Source>();
  private List<Source> mSources = new ArrayList<Source>();
  private TachyonMetricRegistry mMetricRegistry = new TachyonMetricRegistry();
  private MetricsConfig mMetricsConfig;
  private boolean mRunning = false;
  private TachyonConf mTachyonConf;
  private MetricsServlet mMetricsServlet;

  /**
   * Gets the sinks.
   *
   * @return a list of registered Sinks
   */
  public List<Sink> getSinks() {
    return mSinks;
  }

  /**
   * Gets the sources. Used by unit tests only.
   *
   * @return a list of registered Sources
   */
  public List<Source> getSources() {
    return mSources;
  }

  /**
   * Checks if the poll period is smaller that the minimal poll period which is 1 second.
   *
   * @param pollUnit the polling unit
   * @param pollPeriod the polling period
   * @throws IllegalArgumentException if the polling period is invalid
   */
  public static void checkMinimalPollingPeriod(TimeUnit pollUnit, int pollPeriod)
      throws IllegalArgumentException {
    int period = (int) MINIMAL_POLL_UNIT.convert(pollPeriod, pollUnit);
    if (period < MINIMAL_POLL_PERIOD) {
      throw new IllegalArgumentException("Polling period " + pollPeriod + " " + pollUnit
          + " is below than minimal polling period");
    }
  }

  /**
   * Creates a {@code MetricsSystem} using the default metrics config.
   *
   * @param instance the instance name
   * @param tachyonConf the {@link TachyonConf} instance for configuration properties
   * @param defaultSources default sources to register
   */
  public MetricsSystem(String instance, TachyonConf tachyonConf, Source... defaultSources) {
    mInstance = instance;
    mTachyonConf = tachyonConf;
    String metricsConfFile = mTachyonConf.get(Constants.METRICS_CONF_FILE);
    mMetricsConfig = new MetricsConfig(metricsConfFile);
    mDefaultSources = Arrays.asList(defaultSources);
  }

  /**
   * Creates a {@code MetricsSystem} using the given {@code MetricsConfig}.
   *
   * @param instance the instance name
   * @param metricsConfig the {@code MetricsConfig} object
   * @param tachyonConf the {@link TachyonConf} instance for configuration properties
   */
  protected MetricsSystem(String instance, MetricsConfig metricsConfig, TachyonConf tachyonConf) {
    mInstance = instance;
    mMetricsConfig = metricsConfig;
    mTachyonConf = tachyonConf;
  }

  /***
   * Gets the {@link ServletContextHandler} of the metrics servlet.
   *
   * @return the ServletContextHandler if the metrics system is running and the metrics servlet
   *         exists, otherwise null
   */
  public ServletContextHandler getServletHandler() {
    if (mRunning && mMetricsServlet != null) {
      return mMetricsServlet.getHandler();
    }
    return null;
  }

  /**
   * Registers a {@link Source}.
   *
   * @param source the source to register
   */
  public void registerSource(Source source) {
    Preconditions.checkNotNull(mMetricRegistry);
    Preconditions.checkState(mSinks.size() > 0);
    mSources.add(source);
    try {

      if (mMetricRegistry.isHistoryEnabled()) {

        CSVFormat csvFileFormat = CSVFormat.DEFAULT.withRecordSeparator("\n");

        for (Map.Entry<String, Metric> entry : source.getMetricRegistry().getMetrics().entrySet()) {
          try {
            if (entry.getValue() instanceof Counter) {

              String fileName = new StringBuilder().append(mMetricRegistry.getCsvPath()).append("/")
                  .append(mInstance).append(".").append(entry.getKey()).append(".csv").toString();

              CSVParser csvFileParser = new CSVParser(new FileReader(fileName), csvFileFormat);

              CSVRecord currentRecord = Iterables.getLast(csvFileParser.getRecords());
              LOG.debug("increasing metric " + entry.getKey() + " by " + currentRecord.get(1));
              ((Counter) entry.getValue()).inc(Integer.parseInt(currentRecord.get(1)));
            }
          } catch (FileNotFoundException fnf) {
            LOG.debug("Cannot find csv file for metric {} {}", entry.getKey(), fnf.getMessage());
          } catch (IOException io) {
            LOG.warn("Cannot read last value from csv for metric {} {}", entry.getKey(),
                io.getMessage());
          }
        }
      }

      mMetricRegistry.register(source.getName(), source.getMetricRegistry());
    } catch (IllegalArgumentException e) {
      LOG.warn("Metrics already registered. Exception: {}", e.getMessage());
    }
  }

  /**
   * Registers default sources all the sources configured in the metrics config.
   */
  private void registerSources() {
    for (Source source: mDefaultSources) {
      registerSource(source);
    }
    Properties instConfig = mMetricsConfig.getInstanceProperties(mInstance);
    Map<String, Properties> sourceConfigs = mMetricsConfig.subProperties(instConfig, SOURCE_REGEX);
    for (Map.Entry<String, Properties> entry : sourceConfigs.entrySet()) {
      String classPath = entry.getValue().getProperty("class");
      if (classPath != null) {
        try {
          Source source = (Source) Class.forName(classPath).newInstance();
          registerSource(source);
        } catch (Exception e) {
          LOG.error("Source class {} cannot be instantiated", classPath, e);
        }
      }
    }
  }

  /**
   * Registers all the sinks configured in the metrics config.
   */
  private void registerSinks() {
    Properties instConfig = mMetricsConfig.getInstanceProperties(mInstance);
    Map<String, Properties> sinkConfigs = mMetricsConfig.subProperties(instConfig, SINK_REGEX);
    for (Map.Entry<String, Properties> entry : sinkConfigs.entrySet()) {
      String classPath = entry.getValue().getProperty("class");
      if (classPath != null) {
        try {

          Class<? extends Sink> clazz = Class.forName(classPath).asSubclass(Sink.class);

          Sink sink =
                  clazz.getConstructor(Properties.class, MetricRegistry.class)
                          .newInstance(entry.getValue(), mMetricRegistry);

          if (clazz.equals(CsvSink.class)) {
            mMetricRegistry.setHistoryEnabled(true);
            mMetricRegistry.setCsvPath(((CsvSink) sink).getPollDir());
          }

          if (entry.getKey().equals("servlet")) {
            mMetricsServlet = (MetricsServlet) sink;
          } else {
            mSinks.add(sink);
          }
        } catch (Exception e) {
          LOG.error("Sink class {} cannot be instantiated", classPath, e);
        }
      }
    }
  }

  /**
   * Removes a {@link Source}.
   *
   * @param source the source to remove
   */
  public void removeSource(Source source) {
    mSources.remove(source);
    mMetricRegistry.remove(source.getName());
  }

  /**
   * Reports metrics values to all sinks.
   */
  public void report() {
    for (Sink sink : mSinks) {
      sink.report();
    }
  }

  /**
   * Starts the metrics system.
   */
  public void start() {
    if (!mRunning) {
      registerSinks();
      registerSources();
      for (Sink sink : mSinks) {
        sink.start();
      }
      mRunning = true;
    } else {
      LOG.warn("Attempting to start a MetricsSystem that is already running");
    }
  }

  /**
   * Stops the metrics system.
   */
  public void stop() {
    if (mRunning) {
      for (Sink sink : mSinks) {
        sink.stop();
      }
      mRunning = false;
    } else {
      LOG.warn("Stopping a MetricsSystem that is not running");
    }
  }

  /**
   * @return the metric registry
   */
  public TachyonMetricRegistry getMetricRegistry() {
    return mMetricRegistry;
  }
}
